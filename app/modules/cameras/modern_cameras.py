"""
Modern WiFi Camera Auditor - Tests for Eufy, Wyze, Tapo, Ring, Arlo,
Reolink, Imou, Blink, Nest and other modern smart cameras.

Covers:
- mDNS/Bonjour service discovery (_http._tcp, _rtsp._tcp, _hap._tcp)
- Eufy HomeBase P2P + unencrypted stream (CVE-2023-23576)
- Wyze TUTK/Kalay + local API
- Tapo/TP-Link local TLS protocol + KLAP handshake
- Reolink local API (cgi-bin/api.cgi)
- HomeKit Accessory Protocol (HAP) detection
- WebRTC / STUN endpoint detection
- BLE pairing mode detection (via bluetoothctl)
- Cloud API endpoint enumeration
- Certificate pinning analysis (TLS fingerprinting)
- gRPC / HTTP/2 detection
- Matter/Thread border router detection
"""

import socket
import struct
import ssl
import json
import re
import subprocess
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed


# ───────────────────────────────────────────────────────────────
# Modern camera service ports
# ───────────────────────────────────────────────────────────────
MODERN_CAMERA_PORTS = {
    # Eufy / HomeBase
    8080: "Eufy HomeBase HTTP",
    554: "RTSP (Eufy local stream)",
    9001: "Eufy P2P",
    32100: "TUTK P2P (Eufy/Wyze)",

    # Wyze
    8443: "Wyze HTTPS",
    8888: "Wyze local",

    # Tapo / TP-Link
    443: "Tapo HTTPS local",
    20002: "Tapo discovery",

    # Reolink
    9000: "Reolink media",
    1935: "Reolink RTMP",

    # HomeKit
    51827: "HAP (HomeKit)",

    # Matter / Thread
    5540: "Matter commissioning",
    5683: "CoAP (Matter)",

    # Generic IoT
    1883: "MQTT",
    8883: "MQTT TLS",
    5353: "mDNS",
    3478: "STUN/TURN",

    # gRPC
    50051: "gRPC",
}


# Vendor-specific cloud domains (for DNS-based detection)
VENDOR_CLOUD_DOMAINS = {
    "eufy": ["security-app.eufylife.com", "mysecurity.eufylife.com",
             "p2p-prd.eufylife.com", "ms.eufylife.com"],
    "wyze": ["api.wyzecam.com", "auth-prod.api.wyze.com",
             "wyze-mqtt.wyzecam.com", "tutk.iotcplatform.com"],
    "tapo": ["wap.tplinkcloud.com", "n-eu-wap.tplinkcloud.com",
             "use1-wap.tplinkcloud.com"],
    "ring": ["api.ring.com", "fw.ring.com", "oauth.ring.com",
             "app.ring.com"],
    "arlo": ["my.arlo.com", "myapi.arlo.com", "ocapi-app.arlo.com"],
    "nest": ["nexus.dropcam.com", "nest.com", "home.nest.com"],
    "blink": ["rest-prod.immedia-semi.com", "immedia-semi.com"],
    "reolink": ["home.reolink.com", "p2p.reolink.com"],
    "imou": ["openapi.easy4ip.com", "p2p.easy4ip.com"],
}


# mDNS/Bonjour service types used by cameras
MDNS_SERVICE_TYPES = [
    "_hap._tcp.local",          # HomeKit
    "_rtsp._tcp.local",          # RTSP
    "_http._tcp.local",          # HTTP
    "_homekit._tcp.local",
    "_googlecast._tcp.local",   # Nest
    "_camera._tcp.local",        # Generic
    "_axis-video._tcp.local",   # Axis
    "_matter._tcp.local",        # Matter
    "_matterc._udp.local",       # Matter commissioning
    "_meshcop._udp.local",       # Thread
    "_eufy._tcp.local",          # Eufy (some models)
]


class ModernCameraAuditor:
    def __init__(self, target, port=None, timeout=5, verbose=0):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.findings = []
        self.detected_vendor = None

    def run(self):
        self._mdns_discovery()
        self._fingerprint_vendor()
        self._test_eufy_homebase()
        self._test_eufy_unencrypted_stream()
        self._test_wyze_local_api()
        self._test_tapo_klap()
        self._test_reolink_api()
        self._test_homekit_hap()
        self._test_matter_commissioning()
        self._test_webrtc_stun()
        self._test_grpc_endpoints()
        self._test_certificate_pinning()
        self._test_jwt_token_exposure()
        self._test_ble_pairing_mode()
        self._test_local_ai_endpoints()
        self._test_push_notification_data()
        return self.findings

    # ───────────────────────────────────────────────────────────
    # mDNS / Bonjour Discovery
    # ───────────────────────────────────────────────────────────
    def _mdns_discovery(self):
        """Send mDNS queries to discover advertised services."""
        if self.verbose:
            print("    [i] mDNS/Bonjour service discovery...")

        for service_type in MDNS_SERVICE_TYPES:
            response = self._mdns_query(service_type)
            if response:
                self.findings.append({
                    "type": "mdns_service_advertised",
                    "severity": "low",
                    "title": f"mDNS Service Advertised: {service_type}",
                    "description": f"Camera advertises {service_type} via Bonjour",
                    "target": f"{self.target}:5353/udp",
                    "evidence": f"Response: {response[:80].hex() if isinstance(response, bytes) else response[:200]}"
                })
                if self.verbose:
                    print(f"    [+] mDNS: {service_type}")

    def _mdns_query(self, service_name):
        """Build and send an mDNS PTR query."""
        try:
            # Build DNS query packet
            tid = os.urandom(2)
            flags = b"\x00\x00"  # Standard query
            counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 question

            # Encode service name
            qname = b""
            for label in service_name.split("."):
                if label:
                    qname += bytes([len(label)]) + label.encode()
            qname += b"\x00"
            qtype = b"\x00\x0c"  # PTR
            qclass = b"\x00\x01"  # IN

            packet = tid + flags + counts + qname + qtype + qclass

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(packet, (self.target, 5353))

            try:
                data, _ = sock.recvfrom(4096)
                sock.close()
                return data
            except socket.timeout:
                sock.close()
                return None
        except (socket.error, OSError):
            return None

    # ───────────────────────────────────────────────────────────
    # Vendor fingerprinting via HTTP responses + cloud DNS
    # ───────────────────────────────────────────────────────────
    def _fingerprint_vendor(self):
        if self.verbose:
            print("    [i] Fingerprinting modern camera vendor...")

        # Try common HTTP probes
        probes = [
            ("/", 80), ("/", 443), ("/", 8080),
            ("/api/v1/info", 80), ("/info.json", 80),
            ("/cgi-bin/api.cgi", 80),  # Reolink
            ("/app", 8443),  # Wyze
        ]

        for path, port in probes:
            response = self._http_get(path, port, use_ssl=(port in (443, 8443)))
            if not response:
                continue

            response_lower = response.lower()
            vendor_signatures = {
                "eufy": ["eufy", "anker", "eufysecurity"],
                "wyze": ["wyze", "wyzecam"],
                "tapo": ["tapo", "tp-link smart"],
                "ring": ["ring", "ring.com"],
                "arlo": ["arlo", "netgear"],
                "reolink": ["reolink"],
                "imou": ["imou", "easy4ip"],
                "tuya": ["tuya", "smartlife"],
                "blink": ["blink", "immedia"],
                "nest": ["nest", "dropcam"],
            }

            for vendor, sigs in vendor_signatures.items():
                if any(sig in response_lower for sig in sigs):
                    self.detected_vendor = vendor
                    self.findings.append({
                        "type": "modern_camera_vendor",
                        "severity": "info",
                        "title": f"Modern Camera Vendor Detected: {vendor.title()}",
                        "description": f"Camera identified as {vendor} brand",
                        "target": f"http{'s' if port in (443, 8443) else ''}://{self.target}:{port}{path}",
                        "evidence": f"Signature match in response"
                    })
                    if self.verbose:
                        print(f"    [+] Vendor: {vendor}")
                    return

    # ───────────────────────────────────────────────────────────
    # Eufy HomeBase tests
    # ───────────────────────────────────────────────────────────
    def _test_eufy_homebase(self):
        """Test Eufy HomeBase P2P relay protocol."""
        if self.verbose:
            print("    [i] Testing Eufy HomeBase protocol...")

        # Eufy HomeBase listens on TCP 8080 for local API
        # and uses custom P2P over UDP
        eufy_ports = [8080, 9001, 32100]

        for port in eufy_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)

                if sock.connect_ex((self.target, port)) != 0:
                    sock.close()
                    continue

                # Eufy protocol fingerprint - send hello-like probe
                probe = b"\x73\x88\x00\x00\x00\x00\x00\x00"  # Eufy magic-ish
                sock.send(probe)

                try:
                    response = sock.recv(1024)
                    if len(response) > 0:
                        # Check for Eufy-specific response patterns
                        if b"\x73\x88" in response or b"eufy" in response.lower():
                            self.findings.append({
                                "type": "eufy_homebase_exposed",
                                "severity": "high",
                                "title": "Eufy HomeBase Local API Exposed",
                                "description": f"Eufy HomeBase responds on port {port}",
                                "target": f"{self.target}:{port}",
                                "evidence": f"Response: {response[:32].hex()}"
                            })
                            print(f"    [+] Eufy HomeBase on port {port}")
                except socket.timeout:
                    pass
                sock.close()
            except (socket.error, OSError):
                pass

        # Test Eufy local HTTP API
        eufy_paths = [
            "/v1/devices",
            "/v1/local_login",
            "/v1/get_device_info",
            "/api/cameras",
            "/secure_command",
        ]
        for path in eufy_paths:
            response = self._http_get(path, 8080)
            if response and "200" in response.split("\r\n")[0] if response else False:
                self.findings.append({
                    "type": "eufy_local_api",
                    "severity": "high",
                    "title": f"Eufy Local API Endpoint: {path}",
                    "description": "Eufy HomeBase local API accessible",
                    "target": f"http://{self.target}:8080{path}",
                    "evidence": "200 OK response"
                })

    def _test_eufy_unencrypted_stream(self):
        """Test for CVE-2023-23576 / Eufy unencrypted stream issue.
        Eufy was found to leak unencrypted RTSP streams via cloud despite
        E2E encryption claims. Locally, check if RTSP stream lacks encryption.
        """
        if self.verbose:
            print("    [i] Testing Eufy unencrypted stream issue...")

        # Eufy enabled local RTSP feature - test if it's open
        eufy_rtsp_paths = [
            "/live0", "/live1", "/live2",
            "/h264Preview_01_main",
            "/Camera/0",
        ]

        for path in eufy_rtsp_paths:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                if sock.connect_ex((self.target, 554)) != 0:
                    sock.close()
                    return

                request = (
                    f"DESCRIBE rtsp://{self.target}:554{path} RTSP/1.0\r\n"
                    f"CSeq: 1\r\n"
                    f"User-Agent: EufySecurity\r\n"
                    f"\r\n"
                ).encode()
                sock.send(request)
                response = sock.recv(2048).decode("utf-8", errors="replace")
                sock.close()

                if "200 OK" in response and "m=video" in response:
                    # Check if SDP indicates encrypted transport
                    if "RTP/AVP" in response and "RTP/SAVP" not in response:
                        self.findings.append({
                            "type": "eufy_unencrypted_rtsp",
                            "severity": "critical",
                            "title": "Eufy RTSP Stream Unencrypted (CVE-2023-23576 family)",
                            "description": "Local RTSP stream uses RTP/AVP (unencrypted) "
                                          "instead of RTP/SAVP - contradicts E2E claims",
                            "target": f"rtsp://{self.target}:554{path}",
                            "evidence": "SDP shows RTP/AVP transport (no encryption)"
                        })
                        print("    [!] CRITICAL: Eufy unencrypted RTSP stream!")
                        return
            except (socket.error, OSError):
                pass

    # ───────────────────────────────────────────────────────────
    # Wyze tests
    # ───────────────────────────────────────────────────────────
    def _test_wyze_local_api(self):
        """Test Wyze cam local endpoints (RTSP firmware feature)."""
        if self.verbose:
            print("    [i] Testing Wyze local API...")

        # Wyze RTSP firmware exposes /live on port 554
        wyze_endpoints = [
            ("/live", 554, "rtsp"),
            ("/api/info", 8080, "http"),
            ("/local/info", 8888, "http"),
        ]

        for path, port, proto in wyze_endpoints:
            if proto == "rtsp":
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    if sock.connect_ex((self.target, port)) != 0:
                        sock.close()
                        continue

                    request = (
                        f"DESCRIBE rtsp://{self.target}:{port}{path} RTSP/1.0\r\n"
                        f"CSeq: 1\r\nUser-Agent: WyzeApp\r\n\r\n"
                    ).encode()
                    sock.send(request)
                    response = sock.recv(2048)
                    sock.close()

                    if b"WyzeCam" in response or b"wyze" in response.lower():
                        # Check if requires auth
                        if b"401" not in response and b"200" in response:
                            self.findings.append({
                                "type": "wyze_rtsp_unauth",
                                "severity": "critical",
                                "title": "Wyze RTSP Stream Without Auth",
                                "description": "Wyze RTSP firmware exposes stream without authentication",
                                "target": f"rtsp://{self.target}:{port}{path}",
                                "evidence": "200 OK without 401 challenge"
                            })
                            print("    [!] CRITICAL: Wyze RTSP unauthenticated!")
                except (socket.error, OSError):
                    pass

    # ───────────────────────────────────────────────────────────
    # Tapo / TP-Link KLAP protocol
    # ───────────────────────────────────────────────────────────
    def _test_tapo_klap(self):
        """Test TP-Link Tapo KLAP authentication protocol."""
        if self.verbose:
            print("    [i] Testing Tapo KLAP protocol...")

        # Tapo cameras use KLAP (newer firmware) on HTTPS
        tapo_paths = [
            "/app",          # Old protocol (passthrough)
            "/app/handshake1",  # KLAP step 1
            "/app/handshake2",  # KLAP step 2
            "/app/request",
        ]

        for path in tapo_paths:
            response = self._http_get(path, 443, use_ssl=True, method="POST",
                                     body=b'{"method":"handshake","params":{}}')
            if not response:
                continue

            # Tapo returns specific error codes
            if "200" in response.split("\r\n")[0]:
                # KLAP handshake response
                if path == "/app/handshake1":
                    self.findings.append({
                        "type": "tapo_klap_exposed",
                        "severity": "medium",
                        "title": "Tapo KLAP Protocol Endpoint Detected",
                        "description": "Camera uses TP-Link KLAP authentication",
                        "target": f"https://{self.target}:443{path}",
                        "evidence": "KLAP handshake1 returns 200"
                    })
                    if self.verbose:
                        print("    [+] Tapo KLAP detected")

                    # Test KLAP handshake replay/downgrade
                    self._test_tapo_klap_downgrade()
                elif path == "/app":
                    # Old Tapo passthrough - had CVE-2023-27620
                    self.findings.append({
                        "type": "tapo_passthrough_legacy",
                        "severity": "high",
                        "title": "Tapo Legacy Passthrough Protocol",
                        "description": "Camera uses old passthrough protocol "
                                      "(CVE-2023-27620 vulnerable in old firmware)",
                        "target": f"https://{self.target}:443{path}",
                        "evidence": "Legacy /app endpoint accessible"
                    })

    def _test_tapo_klap_downgrade(self):
        """Test if Tapo allows downgrade from KLAP to legacy passthrough."""
        # Send legacy passthrough handshake to KLAP-capable device
        legacy_payload = json.dumps({
            "method": "login_device",
            "params": {
                "username": "admin",
                "password": "admin"
            }
        }).encode()

        response = self._http_get("/app", 443, use_ssl=True,
                                  method="POST", body=legacy_payload)
        if response and "200" in response.split("\r\n")[0]:
            self.findings.append({
                "type": "tapo_klap_downgrade",
                "severity": "high",
                "title": "Tapo KLAP Downgrade Attack Possible",
                "description": "Camera accepts legacy passthrough auth - downgrade attack",
                "target": f"https://{self.target}:443/app",
                "evidence": "Both KLAP and legacy endpoints accessible"
            })

    # ───────────────────────────────────────────────────────────
    # Reolink local API
    # ───────────────────────────────────────────────────────────
    def _test_reolink_api(self):
        """Test Reolink local API."""
        if self.verbose:
            print("    [i] Testing Reolink local API...")

        # Reolink has well-documented local API
        reolink_cmds = [
            "GetDevInfo", "GetAbility", "GetUser",
            "GetNetPort", "GetWifi", "GetP2p", "GetEmail",
        ]

        for cmd in reolink_cmds:
            payload = json.dumps([{
                "cmd": cmd,
                "action": 0,
                "param": {}
            }]).encode()

            response = self._http_get(f"/cgi-bin/api.cgi?cmd={cmd}", 80,
                                      method="POST", body=payload)
            if response and "200" in response.split("\r\n")[0]:
                # Check if response contains data without auth token
                body = response.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in response else ""
                if "value" in body and "rspCode" in body:
                    severity = "critical" if cmd in ("GetUser", "GetWifi") else "high"
                    self.findings.append({
                        "type": "reolink_unauth_api",
                        "severity": severity,
                        "title": f"Reolink Unauthenticated API: {cmd}",
                        "description": f"Reolink {cmd} accessible without authentication token",
                        "target": f"http://{self.target}:80/cgi-bin/api.cgi?cmd={cmd}",
                        "evidence": body[:200]
                    })
                    if self.verbose:
                        print(f"    [+] Reolink unauth: {cmd}")

    # ───────────────────────────────────────────────────────────
    # HomeKit Accessory Protocol
    # ───────────────────────────────────────────────────────────
    def _test_homekit_hap(self):
        """Test HomeKit Accessory Protocol exposure."""
        if self.verbose:
            print("    [i] Testing HomeKit (HAP) protocol...")

        # HAP typically on port 51827 or any port advertised via mDNS
        hap_ports = [51827, 80, 8080, 21063]

        for port in hap_ports:
            # HAP uses HTTP-like protocol with /pair-setup, /pair-verify, /accessories
            response = self._http_get("/accessories", port)
            if response and "200" in response.split("\r\n")[0]:
                body = response.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in response else ""
                if "accessories" in body or "aid" in body or "iid" in body:
                    self.findings.append({
                        "type": "homekit_unpaired_access",
                        "severity": "high",
                        "title": "HomeKit Accessories Endpoint Accessible",
                        "description": "HAP /accessories returns data without pairing",
                        "target": f"http://{self.target}:{port}/accessories",
                        "evidence": body[:200]
                    })
                    print(f"    [+] HomeKit HAP exposed on port {port}")
                    return

            # Try /pair-setup
            response = self._http_get("/pair-setup", port, method="POST",
                                      body=b"\x00\x06\x01\x01\x00\x01\x00")
            if response and ("200" in response.split("\r\n")[0] or "tlv" in response.lower()):
                self.findings.append({
                    "type": "homekit_hap_detected",
                    "severity": "info",
                    "title": "HomeKit HAP Endpoint Detected",
                    "description": "Camera supports HomeKit Accessory Protocol",
                    "target": f"http://{self.target}:{port}/pair-setup",
                    "evidence": "HAP /pair-setup responds"
                })

    # ───────────────────────────────────────────────────────────
    # Matter / Thread
    # ───────────────────────────────────────────────────────────
    def _test_matter_commissioning(self):
        """Test for exposed Matter commissioning service."""
        if self.verbose:
            print("    [i] Testing Matter/Thread protocols...")

        # Matter uses CoAP over UDP 5683 and TCP/UDP 5540
        # Send CoAP discovery
        coap_get = bytes([
            0x40, 0x01,           # Ver=1, Type=Confirmable, Code=GET
            0x00, 0x01,           # Message ID
            0xb1, 0x2e,           # Option: Uri-Path "."
            0x04, 0x77, 0x65, 0x6c, 0x6c,  # "well"
            0x09, 0x6b, 0x6e, 0x6f, 0x77, 0x6e,  # "known"
        ])

        for port in [5683, 5540]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(coap_get, (self.target, port))

                try:
                    response, _ = sock.recvfrom(1024)
                    if len(response) > 4:
                        self.findings.append({
                            "type": "matter_service_exposed",
                            "severity": "medium",
                            "title": "Matter/CoAP Service Detected",
                            "description": f"Camera responds to CoAP probes (Matter protocol)",
                            "target": f"{self.target}:{port}/udp",
                            "evidence": f"CoAP response: {response[:32].hex()}"
                        })
                        if self.verbose:
                            print(f"    [+] Matter/CoAP on port {port}")
                except socket.timeout:
                    pass
                sock.close()
            except (socket.error, OSError):
                pass

    # ───────────────────────────────────────────────────────────
    # WebRTC / STUN
    # ───────────────────────────────────────────────────────────
    def _test_webrtc_stun(self):
        """Test for STUN/TURN endpoints used by cloud cameras."""
        if self.verbose:
            print("    [i] Testing WebRTC/STUN endpoints...")

        # STUN binding request (RFC 5389)
        stun_request = bytes([
            0x00, 0x01,             # Binding Request
            0x00, 0x00,             # Length
            0x21, 0x12, 0xa4, 0x42, # Magic cookie
        ]) + os.urandom(12)         # Transaction ID

        for port in [3478, 19302, 5349]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(stun_request, (self.target, port))

                try:
                    response, _ = sock.recvfrom(1024)
                    # STUN binding success = 0x0101
                    if len(response) >= 20 and response[0:2] == b"\x01\x01":
                        self.findings.append({
                            "type": "webrtc_stun_exposed",
                            "severity": "low",
                            "title": "STUN Server Detected",
                            "description": f"Camera/relay runs STUN server on port {port}",
                            "target": f"{self.target}:{port}/udp",
                            "evidence": "STUN binding response received"
                        })
                        if self.verbose:
                            print(f"    [+] STUN on port {port}")
                except socket.timeout:
                    pass
                sock.close()
            except (socket.error, OSError):
                pass

    # ───────────────────────────────────────────────────────────
    # gRPC / HTTP/2 detection
    # ───────────────────────────────────────────────────────────
    def _test_grpc_endpoints(self):
        """Test for gRPC endpoints (Wyze, some Arlo models use gRPC)."""
        if self.verbose:
            print("    [i] Testing gRPC endpoints...")

        grpc_ports = [50051, 443, 8443]

        for port in grpc_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)

                if port in (443, 8443):
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.set_alpn_protocols(["h2"])  # HTTP/2 ALPN
                    sock = ctx.wrap_socket(sock, server_hostname=self.target)

                if sock.connect_ex((self.target, port)) != 0:
                    sock.close()
                    continue

                # Check ALPN negotiation
                if hasattr(sock, "selected_alpn_protocol"):
                    alpn = sock.selected_alpn_protocol()
                    if alpn == "h2":
                        # Send HTTP/2 connection preface
                        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                        sock.send(preface)

                        # Read SETTINGS frame from server
                        try:
                            response = sock.recv(64)
                            if len(response) > 0 and response[3] == 0x04:  # SETTINGS frame
                                self.findings.append({
                                    "type": "http2_grpc_detected",
                                    "severity": "info",
                                    "title": f"HTTP/2 (gRPC capable) on port {port}",
                                    "description": "Camera supports HTTP/2 - likely gRPC backend",
                                    "target": f"https://{self.target}:{port}",
                                    "evidence": f"ALPN: h2, SETTINGS frame received"
                                })
                                if self.verbose:
                                    print(f"    [+] HTTP/2 on port {port}")
                        except socket.timeout:
                            pass
                sock.close()
            except (socket.error, ssl.SSLError, OSError):
                pass

    # ───────────────────────────────────────────────────────────
    # Certificate pinning analysis
    # ───────────────────────────────────────────────────────────
    def _test_certificate_pinning(self):
        """Analyze TLS certificate to detect pinning weaknesses."""
        if self.verbose:
            print("    [i] Analyzing TLS certificate...")

        for port in [443, 8443]:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock = ctx.wrap_socket(sock, server_hostname=self.target)

                if sock.connect_ex((self.target, port)) != 0:
                    sock.close()
                    continue

                cert_der = sock.getpeercert(binary_form=True)
                cert = sock.getpeercert(binary_form=False) or {}

                # Check for self-signed cert
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))

                if issuer == subject:
                    self.findings.append({
                        "type": "tls_self_signed",
                        "severity": "medium",
                        "title": "Self-Signed TLS Certificate",
                        "description": "Camera uses self-signed cert - "
                                      "MITM possible if no pinning client-side",
                        "target": f"{self.target}:{port}",
                        "evidence": f"Subject: {subject.get('commonName', 'N/A')}"
                    })

                # Check for expired
                not_after = cert.get("notAfter", "")
                if not_after:
                    try:
                        from datetime import datetime
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        if exp < datetime.now():
                            self.findings.append({
                                "type": "tls_expired",
                                "severity": "high",
                                "title": "TLS Certificate Expired",
                                "description": "Camera serves expired TLS certificate",
                                "target": f"{self.target}:{port}",
                                "evidence": f"Expired: {not_after}"
                            })
                    except (ValueError, TypeError):
                        pass

                # Check for weak key
                if cert.get("subjectAltName"):
                    sans = [s[1] for s in cert["subjectAltName"]]
                    if any(san in ("localhost", "127.0.0.1", "*") for san in sans):
                        self.findings.append({
                            "type": "tls_weak_san",
                            "severity": "medium",
                            "title": "Weak TLS Certificate SAN",
                            "description": "Certificate has overly permissive SAN entries",
                            "target": f"{self.target}:{port}",
                            "evidence": f"SANs: {sans}"
                        })

                sock.close()
            except (socket.error, ssl.SSLError, OSError):
                pass

    # ───────────────────────────────────────────────────────────
    # JWT / OAuth token exposure
    # ───────────────────────────────────────────────────────────
    def _test_jwt_token_exposure(self):
        """Test for exposed JWT tokens or OAuth credentials."""
        if self.verbose:
            print("    [i] Testing for JWT/OAuth token exposure...")

        jwt_paths = [
            "/api/v1/auth/token",
            "/oauth/token",
            "/.well-known/openid-configuration",
            "/api/auth/info",
            "/auth/refresh",
            "/api/v1/cloud/token",
            "/api/token",
        ]

        for path in jwt_paths:
            for port in [80, 443, 8080, 8443]:
                response = self._http_get(path, port,
                                         use_ssl=(port in (443, 8443)))
                if not response:
                    continue

                if "200" in response.split("\r\n")[0]:
                    body = response.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in response else ""

                    # Look for JWT pattern (eyJ...)
                    jwt_match = re.search(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", body)
                    if jwt_match:
                        self.findings.append({
                            "type": "jwt_token_leaked",
                            "severity": "critical",
                            "title": "JWT Token Exposed",
                            "description": f"JWT token leaked at {path}",
                            "target": f"http{'s' if port in (443, 8443) else ''}://{self.target}:{port}{path}",
                            "evidence": f"JWT prefix: {jwt_match.group()[:50]}..."
                        })
                        print(f"    [!] CRITICAL: JWT exposed at {path}")
                        return

                    # OAuth/OIDC config disclosure
                    if "issuer" in body or "token_endpoint" in body:
                        self.findings.append({
                            "type": "oauth_config_exposed",
                            "severity": "low",
                            "title": "OAuth/OIDC Configuration Disclosed",
                            "description": f"OAuth config accessible at {path}",
                            "target": f"http{'s' if port in (443, 8443) else ''}://{self.target}:{port}{path}",
                            "evidence": "OpenID config visible without auth"
                        })

    # ───────────────────────────────────────────────────────────
    # BLE pairing mode detection
    # ───────────────────────────────────────────────────────────
    def _test_ble_pairing_mode(self):
        """Detect if camera is broadcasting in BLE pairing mode."""
        if self.verbose:
            print("    [i] Checking BLE pairing mode (requires bluetoothctl)...")

        try:
            result = subprocess.run(
                ["bluetoothctl", "--timeout", "5", "scan", "on"],
                capture_output=True, text=True, timeout=8
            )

            if result.returncode != 0:
                if self.verbose:
                    print("    [i] BLE scan unavailable")
                return

            output = result.stdout
            camera_ble_keywords = [
                "eufy", "wyze", "tapo", "ring", "arlo", "nest",
                "blink", "reolink", "imou", "tp-link", "camera",
                "ipc", "doorbell", "hb3", "homebase",
            ]

            for line in output.split("\n"):
                if "Device" in line and "NEW" in line.upper():
                    line_lower = line.lower()
                    for keyword in camera_ble_keywords:
                        if keyword in line_lower:
                            # Extract MAC and name
                            parts = line.split()
                            if len(parts) >= 3:
                                mac = parts[2]
                                name = " ".join(parts[3:])

                                self.findings.append({
                                    "type": "ble_pairing_mode",
                                    "severity": "high",
                                    "title": "Camera in BLE Pairing Mode",
                                    "description": f"Camera broadcasting via BLE - "
                                                  f"may be pairable without auth",
                                    "target": mac,
                                    "evidence": f"BLE name: {name}"
                                })
                                if self.verbose:
                                    print(f"    [+] BLE pairing: {name} ({mac})")
                                break
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            if self.verbose:
                print("    [i] BLE scan skipped (bluetoothctl not available)")

    # ───────────────────────────────────────────────────────────
    # Local AI/ML endpoints
    # ───────────────────────────────────────────────────────────
    def _test_local_ai_endpoints(self):
        """Test for local AI/ML inference endpoints (face/person detection)."""
        if self.verbose:
            print("    [i] Testing local AI/ML endpoints...")

        ai_paths = [
            "/api/v1/ai/inference",
            "/ai/face_recognition",
            "/api/detect",
            "/inference",
            "/api/v1/persons",
            "/api/v1/faces",
            "/cgi-bin/ai_detect.cgi",
            "/api/v1/events/face",
            "/SDK/AI/faceDetect",
        ]

        for path in ai_paths:
            for port in [80, 443, 8080]:
                response = self._http_get(path, port,
                                         use_ssl=(port == 443))
                if response and "200" in response.split("\r\n")[0]:
                    body = response.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in response else ""
                    if any(k in body.lower() for k in ["face", "person", "detect", "recognition", "embedding"]):
                        self.findings.append({
                            "type": "ai_endpoint_exposed",
                            "severity": "high",
                            "title": f"Local AI/ML Endpoint Exposed",
                            "description": f"AI inference endpoint at {path} - "
                                          f"may leak biometric data",
                            "target": f"http{'s' if port == 443 else ''}://{self.target}:{port}{path}",
                            "evidence": body[:200]
                        })
                        if self.verbose:
                            print(f"    [+] AI endpoint: {path}")

    # ───────────────────────────────────────────────────────────
    # Push notification data leak
    # ───────────────────────────────────────────────────────────
    def _test_push_notification_data(self):
        """Test for endpoints related to push notifications with images.

        Some cameras (Eufy was found doing this) include unencrypted
        thumbnails in push notifications via cloud.
        """
        if self.verbose:
            print("    [i] Testing push notification config...")

        push_paths = [
            "/api/v1/notifications/config",
            "/api/push/config",
            "/cgi-bin/push.cgi",
            "/api/v1/events/list",
            "/api/v1/snapshots",
            "/snapshots/recent",
        ]

        for path in push_paths:
            for port in [80, 443, 8080]:
                response = self._http_get(path, port,
                                         use_ssl=(port == 443))
                if response and "200" in response.split("\r\n")[0]:
                    body = response.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in response else ""

                    # Check for thumbnail URLs or base64 images in response
                    if any(p in body for p in ["base64", "thumbnail", "snapshot_url", "image_url"]):
                        self.findings.append({
                            "type": "push_notification_data_leak",
                            "severity": "high",
                            "title": "Push Notification Thumbnails Exposed",
                            "description": f"Camera exposes notification thumbnails "
                                          f"at {path} - similar to Eufy push leak",
                            "target": f"http{'s' if port == 443 else ''}://{self.target}:{port}{path}",
                            "evidence": "Thumbnail/image URLs in response"
                        })
                        if self.verbose:
                            print(f"    [+] Push thumbnails: {path}")

    # ───────────────────────────────────────────────────────────
    # Helper: HTTP GET/POST
    # ───────────────────────────────────────────────────────────
    def _http_get(self, path, port, use_ssl=False, method="GET", body=None):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.target)

            if sock.connect_ex((self.target, port)) != 0:
                sock.close()
                return None

            request = f"{method} {path} HTTP/1.1\r\n"
            request += f"Host: {self.target}\r\n"
            request += "User-Agent: CameraAudit/1.0\r\n"
            request += "Connection: close\r\n"

            if body:
                request += f"Content-Length: {len(body)}\r\n"
                request += "Content-Type: application/json\r\n"
                request += "\r\n"
                full_request = request.encode() + body
            else:
                request += "\r\n"
                full_request = request.encode()

            sock.send(full_request)
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 65536:
                        break
                except socket.timeout:
                    break
            sock.close()
            return response.decode("utf-8", errors="replace")
        except (socket.error, ssl.SSLError, OSError):
            return None
