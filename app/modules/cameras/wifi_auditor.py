"""
WiFi Camera Auditor - Tests vulnerabilities specific to wireless cameras.
Covers: P2P protocol abuse (PPPP/TUTK/Kalay), cloud API exposure,
WiFi credential leaks, deauth resilience, AP mode defaults,
Tuya/Smart Life protocol, UDP discovery, MQTT sniffing vectors.
"""

import socket
import struct
import time
import os
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


# P2P camera ports (PPPP protocol, TUTK/Kalay, etc.)
P2P_PORTS = [
    10000, 10001, 10002, 10003,  # Common PPPP
    32100, 32108, 32761,          # TUTK/Kalay
    2049, 2015, 2016,             # iCSee/XMEye
    8800, 8899, 9008,             # CamHi/HiChip
    6667, 6668,                   # Yoosee
    34567, 34568,                 # XMEye binary
    20188,                        # Smart Life/Tuya local
    6666, 6668, 7000, 7681,       # Various P2P
]

# PPPP magic bytes for different implementations
PPPP_MAGIC = {
    b"\xf1\x00": "PPPP (CS2 Network)",
    b"\xf1\xd0": "PPPP (Shenzhen Yunni)",
    b"\xf1\xe0": "PPPP (iLnkP2P)",
    b"\xf1\x20": "PPPP (HiChip/CamHi)",
    b"\xf1\x30": "PPPP (Kalay/TUTK v1)",
    b"\xf1\x40": "PPPP (Kalay/TUTK v2)",
}

# Tuya local protocol constants
TUYA_PREFIX = b"\x00\x00\x55\xaa"
TUYA_SUFFIX = b"\x00\x00\xaa\x55"

# Known WiFi camera cloud domains for DNS enumeration
WIFI_CAM_CLOUDS = [
    "p2p.tutk.com", "p2p1.tutk.com", "p2p2.tutk.com",
    "m2.tutk.com", "a1.tuyacn.com", "a1.tuyaus.com",
    "a1.tuyaeu.com", "openapi.tuyaus.com",
    "p2p.cloudlinks.cn", "p2p.tenvis.com",
    "p2p.eye4.cn", "p2p.yoosee.co",
    "cloud.cs2-network.com", "pppp.cs2-network.com",
    "ntp.cs2-network.com", "tracker.cs2-network.com",
    "api.xiongmaitech.com", "cloud.icseecamera.com",
    "mqtt.smart-camera.net",
]


class WiFiAuditor:
    def __init__(self, target, port=None, timeout=5, verbose=0,
                 interface=None):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.interface = interface or "wlan0"
        self.findings = []

    def run(self):
        self._scan_p2p_services()
        self._test_pppp_protocol()
        self._test_tutk_kalay()
        self._test_tuya_local()
        self._test_xmeye_protocol()
        self._test_wifi_credential_exposure()
        self._test_cloud_api_exposure()
        self._test_udp_discovery()
        self._test_mqtt_exposure()
        self._test_firmware_update_mitm()
        self._test_ap_mode_defaults()
        self._test_p2p_uid_bruteforce()
        return self.findings

    def _scan_p2p_services(self):
        """Scan for P2P camera services on known ports."""
        if self.verbose:
            print("    [i] Scanning P2P camera service ports...")

        open_ports = []

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                if sock.connect_ex((self.target, port)) == 0:
                    sock.close()
                    return port
                sock.close()
            except (socket.error, OSError):
                pass

            # Also check UDP
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(b"\x00" * 4, (self.target, port))
                try:
                    data, _ = sock.recvfrom(1024)
                    sock.close()
                    return port
                except socket.timeout:
                    sock.close()
            except (socket.error, OSError):
                pass
            return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_port, p): p for p in P2P_PORTS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    if self.verbose:
                        print(f"    [+] P2P port open: {result}")

        if open_ports:
            self.findings.append({
                "type": "wifi_p2p_services",
                "severity": "medium",
                "title": "P2P Camera Services Detected",
                "description": f"Found {len(open_ports)} P2P service port(s) open",
                "target": self.target,
                "evidence": open_ports
            })

    def _test_pppp_protocol(self):
        """Test PPPP (Point-to-Point Protocol for cameras) vulnerabilities."""
        if self.verbose:
            print("    [i] Testing PPPP protocol vulnerabilities...")

        # PPPP typically runs on UDP 32100 or similar
        pppp_ports = [32100, 32108, 10000, 10001, 32761]

        for port in pppp_ports:
            # Send PPPP discovery/hello packet
            # Different PPPP implementations use different magic bytes
            for magic, vendor in PPPP_MAGIC.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(3)

                    # PPPP MSG_HELLO (type 0x00)
                    hello_packet = magic + b"\x00\x00"  # magic + msg type
                    hello_packet += b"\x00\x00\x00\x00"  # sequence
                    hello_packet += b"\x00" * 20  # padding/uid placeholder

                    sock.sendto(hello_packet, (self.target, port))

                    try:
                        response, addr = sock.recvfrom(1024)
                        if len(response) > 4 and response[:2] in PPPP_MAGIC:
                            self.findings.append({
                                "type": "wifi_pppp_exposed",
                                "severity": "high",
                                "title": f"PPPP Protocol Exposed ({vendor})",
                                "description": f"Camera exposes PPPP P2P service on port {port}",
                                "target": f"{self.target}:{port}/udp",
                                "evidence": f"Vendor: {vendor}, Response: {response[:32].hex()}"
                            })
                            print(f"    [+] PPPP service found: {vendor} on port {port}")

                            # Test for CVE-2019-11219 (iLnkP2P info disclosure)
                            self._test_pppp_info_disclosure(sock, port, magic)
                            break
                    except socket.timeout:
                        pass
                    sock.close()
                except (socket.error, OSError):
                    pass

    def _test_pppp_info_disclosure(self, sock, port, magic):
        """CVE-2019-11219: PPPP information disclosure via crafted packets."""
        # MSG_PUNCH_TO (0x41) - can leak internal IP/port info
        punch_packet = magic + b"\x41\x00"
        punch_packet += b"\x00\x00\x00\x01"  # sequence
        punch_packet += b"\x00" * 24

        try:
            sock.sendto(punch_packet, (self.target, port))
            response, _ = sock.recvfrom(1024)

            if len(response) > 20:
                self.findings.append({
                    "type": "wifi_pppp_cve_2019_11219",
                    "severity": "critical",
                    "title": "CVE-2019-11219: PPPP Information Disclosure",
                    "description": "Camera leaks internal network info via PPPP MSG_PUNCH",
                    "target": f"{self.target}:{port}/udp",
                    "evidence": f"Response to MSG_PUNCH: {response[:64].hex()}"
                })
                print("    [!] CRITICAL: PPPP info disclosure (CVE-2019-11219)")
        except (socket.timeout, socket.error):
            pass

    def _test_tutk_kalay(self):
        """Test TUTK/Kalay P2P platform vulnerabilities."""
        if self.verbose:
            print("    [i] Testing TUTK/Kalay P2P protocol...")

        # Kalay typically uses UDP 32100
        port = 32100

        # CVE-2021-28372: TUTK P2P SDK access bypass
        # Send crafted device binding request
        tutk_hello = struct.pack(
            ">HHI",
            0xF130,  # TUTK magic
            0x0000,  # MSG_TYPE: HELLO
            0x00000001  # Session ID
        )
        tutk_hello += b"\x00" * 32  # UID placeholder

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(tutk_hello, (self.target, port))

            try:
                response, _ = sock.recvfrom(2048)
                if len(response) > 8:
                    # Parse TUTK response
                    self.findings.append({
                        "type": "wifi_tutk_exposed",
                        "severity": "high",
                        "title": "TUTK/Kalay P2P Service Exposed",
                        "description": "Camera runs TUTK P2P SDK - potential CVE-2021-28372",
                        "target": f"{self.target}:{port}/udp",
                        "evidence": f"TUTK response: {response[:48].hex()}"
                    })
                    print("    [+] TUTK/Kalay P2P detected")

                    # Test for auth bypass
                    self._test_tutk_auth_bypass(port)
            except socket.timeout:
                pass
            sock.close()
        except (socket.error, OSError):
            pass

    def _test_tutk_auth_bypass(self, port):
        """CVE-2021-28372: Test TUTK authentication bypass."""
        # Attempt to establish session without proper auth token
        session_req = struct.pack(">HHI", 0xF130, 0x0010, 0x00000001)
        session_req += b"\x00" * 20  # Empty auth token
        session_req += b"AAAAAAAAAAAAAAAA"  # Fake UID

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(session_req, (self.target, port))

            try:
                response, _ = sock.recvfrom(2048)
                # If we get a session acknowledgement without proper auth
                if len(response) > 8 and response[2:4] == b"\x00\x11":
                    self.findings.append({
                        "type": "wifi_tutk_auth_bypass",
                        "severity": "critical",
                        "title": "CVE-2021-28372: TUTK Authentication Bypass",
                        "description": "Camera accepts P2P sessions without authentication",
                        "target": f"{self.target}:{port}/udp",
                        "evidence": f"Session accepted: {response[:32].hex()}"
                    })
                    print("    [!] CRITICAL: TUTK auth bypass!")
            except socket.timeout:
                pass
            sock.close()
        except (socket.error, OSError):
            pass

    def _test_tuya_local(self):
        """Test Tuya/Smart Life local protocol vulnerabilities."""
        if self.verbose:
            print("    [i] Testing Tuya/Smart Life local protocol...")

        # Tuya cameras listen on TCP 6668 for local control
        tuya_ports = [6668, 6667, 20188]

        for port in tuya_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)

                if sock.connect_ex((self.target, port)) != 0:
                    sock.close()
                    continue

                # Tuya protocol: prefix(4) + seq(4) + cmd(4) + len(4) + data + crc(4) + suffix(4)
                # CMD 0x0a = STATUS request (often works without auth on local network)
                seq_num = 1
                cmd = 0x0a  # DP_QUERY
                data = b'{"devId":"","uid":"","t":"0"}'

                payload = struct.pack(">III", seq_num, cmd, len(data) + 8)
                payload += data
                # CRC32 placeholder
                import binascii
                crc = binascii.crc32(payload) & 0xFFFFFFFF
                payload += struct.pack(">I", crc)

                full_packet = TUYA_PREFIX + payload + TUYA_SUFFIX
                sock.send(full_packet)

                try:
                    response = sock.recv(4096)
                    if TUYA_PREFIX in response or len(response) > 20:
                        self.findings.append({
                            "type": "wifi_tuya_local",
                            "severity": "high",
                            "title": "Tuya Local Protocol Exposed",
                            "description": f"Camera responds to Tuya local commands on port {port}",
                            "target": f"{self.target}:{port}",
                            "evidence": f"Response: {response[:64].hex()}"
                        })
                        print(f"    [+] Tuya local protocol on port {port}")

                        # Test for local key exposure
                        self._test_tuya_key_exposure(sock, port)
                except socket.timeout:
                    pass
                sock.close()
            except (socket.error, OSError):
                pass

    def _test_tuya_key_exposure(self, sock, port):
        """Test if Tuya device exposes local encryption key."""
        # Some Tuya devices respond to unencrypted status queries
        # revealing device state without knowing the local key
        cmd = 0x12  # HEART_BEAT (some devices leak info here)
        data = b'{}'
        seq_num = 2

        payload = struct.pack(">III", seq_num, cmd, len(data) + 8)
        payload += data
        import binascii
        crc = binascii.crc32(payload) & 0xFFFFFFFF
        payload += struct.pack(">I", crc)

        full_packet = TUYA_PREFIX + payload + TUYA_SUFFIX
        try:
            sock.send(full_packet)
            response = sock.recv(4096)
            if b"dps" in response or b"devId" in response:
                self.findings.append({
                    "type": "wifi_tuya_unencrypted",
                    "severity": "critical",
                    "title": "Tuya Camera Responds Without Encryption",
                    "description": "Device state accessible without local encryption key",
                    "target": f"{self.target}:{port}",
                    "evidence": "Device responds to unencrypted queries"
                })
                print("    [!] CRITICAL: Tuya unencrypted access!")
        except (socket.timeout, socket.error):
            pass

    def _test_xmeye_protocol(self):
        """Test XMEye/Xiongmai binary protocol vulnerabilities."""
        if self.verbose:
            print("    [i] Testing XMEye/Xiongmai protocol...")

        port = self.port or 34567

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if sock.connect_ex((self.target, port)) != 0:
                sock.close()
                return

            # XMEye login with empty/default hash
            # Header: 0xff(1) + type(1) + reserved(2) + session(4) + seq(4) + total(4) + cur(4) + msgid(2) + len(4)
            # Login CMD: 0x03e8 (1000)
            login_data = json.dumps({
                "EncryptType": "MD5",
                "LoginType": "DVRIP-Web",
                "PassWord": "",  # Empty password
                "UserName": "admin"
            }).encode()

            # XMEye protocol header
            header = struct.pack("<BBHI", 0xFF, 0x01, 0x0000, 0x00000000)
            header += struct.pack("<III", 0x00000000, 0x00000001, 0x000003E8)
            header += struct.pack("<I", len(login_data))

            sock.send(header + login_data)
            response = sock.recv(4096)

            if len(response) > 20:
                try:
                    # Parse response - look for success indicators
                    resp_text = response[20:].decode("utf-8", errors="replace")
                    if '"Ret"' in resp_text:
                        resp_json = json.loads(resp_text.split("\x00")[0])
                        if resp_json.get("Ret") == 100:  # Success
                            self.findings.append({
                                "type": "wifi_xmeye_default_creds",
                                "severity": "critical",
                                "title": "XMEye/Xiongmai Default Credentials",
                                "description": "Camera accepts login with empty password",
                                "target": f"{self.target}:{port}",
                                "evidence": "Login successful with admin:(empty)"
                            })
                            print("    [!] CRITICAL: XMEye empty password login!")
                        elif resp_json.get("Ret") in (101, 102, 103):
                            # Auth failed but service is there
                            self.findings.append({
                                "type": "wifi_xmeye_exposed",
                                "severity": "medium",
                                "title": "XMEye/Xiongmai Protocol Exposed",
                                "description": "Camera runs XMEye binary protocol",
                                "target": f"{self.target}:{port}",
                                "evidence": f"Login response: Ret={resp_json.get('Ret')}"
                            })
                except (json.JSONDecodeError, IndexError):
                    pass

            sock.close()

            # Test known XMEye backdoor hashes
            self._test_xmeye_backdoor(port)

        except (socket.error, OSError):
            pass

    def _test_xmeye_backdoor(self, port):
        """Test XMEye known backdoor credentials."""
        # Known default password hashes for XMEye/Xiongmai
        backdoor_creds = [
            ("admin", ""),           # Empty
            ("admin", "admin"),
            ("default", "tluafed"),  # "default" reversed - known backdoor
            ("admin", "tlJwpbo6"),   # Known Dahua/XM hash collision
            ("user", "user"),
        ]

        for user, passwd in backdoor_creds[1:]:  # Skip empty, already tested
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, port))

                login_data = json.dumps({
                    "EncryptType": "MD5",
                    "LoginType": "DVRIP-Web",
                    "PassWord": passwd,
                    "UserName": user
                }).encode()

                header = struct.pack("<BBHI", 0xFF, 0x01, 0x0000, 0x00000000)
                header += struct.pack("<III", 0x00000000, 0x00000001, 0x000003E8)
                header += struct.pack("<I", len(login_data))

                sock.send(header + login_data)
                response = sock.recv(4096)
                sock.close()

                if len(response) > 20:
                    resp_text = response[20:].decode("utf-8", errors="replace")
                    if '"Ret" : 100' in resp_text or '"Ret":100' in resp_text:
                        self.findings.append({
                            "type": "wifi_xmeye_backdoor",
                            "severity": "critical",
                            "title": "XMEye Backdoor Credentials Active",
                            "description": f"Camera accepts backdoor credentials: {user}:{passwd}",
                            "target": f"{self.target}:{port}",
                            "evidence": f"Login success with {user}:{passwd}"
                        })
                        print(f"    [!] CRITICAL: XMEye backdoor: {user}:{passwd}")
                        return
            except (socket.error, OSError):
                pass

    def _test_wifi_credential_exposure(self):
        """Test if camera exposes WiFi credentials via various interfaces."""
        if self.verbose:
            print("    [i] Testing WiFi credential exposure...")

        # Many cameras expose WiFi config via HTTP without auth
        http_port = self.port or 80
        wifi_paths = [
            "/cgi-bin/CGIProxy.fcgi?cmd=getWifiList",
            "/cgi-bin/hi3510/param.cgi?cmd=getwirelessattr",
            "/wireless?action=get",
            "/goform/WifiBasicGet",
            "/api/v1/wifi",
            "/wifi/config",
            "/system/network/wifi",
            "/cgi-bin/param.cgi?cmd=getwifiattr",
            "/onvif/device_service",  # Sometimes leaks WiFi SSID
            "/config/wifi.json",
            "/cgi-bin/configManager.cgi?action=getConfig&name=WLan",
            "/LAPI/V1.0/Channels/System/Network/Wireless",
            "/stw-cgi/network.cgi?msubmenu=wireless",
        ]

        for path in wifi_paths:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, http_port))

                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                sock.send(request)

                response = b""
                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    except socket.timeout:
                        break
                sock.close()

                decoded = response.decode("utf-8", errors="replace")

                if "200 OK" in decoded:
                    # Check for WiFi credential indicators
                    wifi_indicators = [
                        "password", "psk", "wpa_key", "wifi_key",
                        "WifiPsk", "KeyValue", "wlan_key", "passphrase",
                        "wireless_key", "WirelessPassword"
                    ]
                    body = decoded.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in decoded else ""

                    for indicator in wifi_indicators:
                        if indicator.lower() in body.lower():
                            self.findings.append({
                                "type": "wifi_credential_exposure",
                                "severity": "critical",
                                "title": "WiFi Credentials Exposed",
                                "description": f"WiFi password accessible at {path}",
                                "target": f"http://{self.target}:{http_port}{path}",
                                "evidence": f"Found '{indicator}' in response"
                            })
                            print(f"    [!] CRITICAL: WiFi creds exposed at {path}")
                            return

                    # Check for SSID exposure (lower severity)
                    ssid_indicators = ["ssid", "SSID", "essid", "network_name"]
                    for indicator in ssid_indicators:
                        if indicator.lower() in body.lower():
                            self.findings.append({
                                "type": "wifi_ssid_exposure",
                                "severity": "medium",
                                "title": "WiFi SSID Information Disclosed",
                                "description": f"WiFi network info accessible at {path}",
                                "target": f"http://{self.target}:{http_port}{path}",
                                "evidence": f"Found '{indicator}' in response"
                            })
                            break

            except (socket.error, OSError):
                pass

    def _test_cloud_api_exposure(self):
        """Test for cloud API endpoints that leak device info."""
        if self.verbose:
            print("    [i] Testing cloud API exposure...")

        http_port = self.port or 80
        cloud_paths = [
            "/api/device/info",
            "/api/cloud/status",
            "/api/v1/cloud",
            "/cgi-bin/p2p.cgi",
            "/p2p/info",
            "/tutk/info",
            "/cloud/token",
            "/api/uid",
            "/device/uid",
            "/System/P2P",
            "/ISAPI/System/P2P",
        ]

        for path in cloud_paths:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, http_port))

                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                sock.send(request)
                response = sock.recv(4096)
                sock.close()

                decoded = response.decode("utf-8", errors="replace")
                if "200 OK" in decoded:
                    body = decoded.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in decoded else ""
                    if any(x in body.lower() for x in ["uid", "p2p", "token", "cloud", "tutk"]):
                        self.findings.append({
                            "type": "wifi_cloud_api_exposed",
                            "severity": "high",
                            "title": f"Cloud/P2P API Endpoint Exposed",
                            "description": f"Cloud control API accessible at {path}",
                            "target": f"http://{self.target}:{http_port}{path}",
                            "evidence": body[:200]
                        })
                        if self.verbose:
                            print(f"    [+] Cloud API exposed: {path}")
            except (socket.error, OSError):
                pass

    def _test_udp_discovery(self):
        """Test UDP-based camera discovery protocols for info leaks."""
        if self.verbose:
            print("    [i] Testing UDP discovery protocols...")

        # Many WiFi cameras respond to broadcast discovery packets
        discovery_probes = [
            # XMEye/Xiongmai discovery
            (34569, b"\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x01\x00\x00\x14", "XMEye Discovery"),
            # Hikvision SADP
            (37020, b"\x00\x00\x00\x20\x44\x48\x49\x50"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x03", "Hikvision SADP"),
            # Dahua discovery
            (5050, b"\xa3\x01\x00\x01\x00\x00\x00\x00"
                   b"\x00\x00\x00\x00\x00\x00\x00\x00", "Dahua Discovery"),
            # Generic SSDP
            (1900, b"M-SEARCH * HTTP/1.1\r\n"
                   b"HOST: 239.255.255.250:1900\r\n"
                   b"MAN: \"ssdp:discover\"\r\n"
                   b"ST: urn:cellvision:device:*\r\n"
                   b"MX: 3\r\n\r\n", "SSDP Camera"),
        ]

        for port, probe, proto_name in discovery_probes:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(probe, (self.target, port))

                try:
                    response, addr = sock.recvfrom(4096)
                    if len(response) > 10:
                        self.findings.append({
                            "type": "wifi_udp_discovery_leak",
                            "severity": "medium",
                            "title": f"UDP Discovery Info Leak ({proto_name})",
                            "description": f"Camera responds to {proto_name} probes",
                            "target": f"{self.target}:{port}/udp",
                            "evidence": f"Response size: {len(response)} bytes, "
                                       f"hex: {response[:48].hex()}"
                        })
                        if self.verbose:
                            print(f"    [+] {proto_name} responds on port {port}")
                except socket.timeout:
                    pass
                sock.close()
            except (socket.error, OSError):
                pass

    def _test_mqtt_exposure(self):
        """Test for exposed MQTT broker used by WiFi cameras."""
        if self.verbose:
            print("    [i] Testing MQTT exposure...")

        mqtt_ports = [1883, 8883]

        for port in mqtt_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)

                if sock.connect_ex((self.target, port)) != 0:
                    sock.close()
                    continue

                # MQTT CONNECT packet (anonymous)
                connect_packet = bytearray([
                    0x10,  # CONNECT packet type
                    0x10,  # Remaining length
                    0x00, 0x04,  # Protocol name length
                    0x4D, 0x51, 0x54, 0x54,  # "MQTT"
                    0x04,  # Protocol level (MQTT 3.1.1)
                    0x02,  # Connect flags (clean session)
                    0x00, 0x3C,  # Keep alive (60s)
                    0x00, 0x04,  # Client ID length
                    0x74, 0x65, 0x73, 0x74,  # Client ID: "test"
                ])

                sock.send(connect_packet)
                response = sock.recv(1024)

                if len(response) >= 4 and response[0] == 0x20:  # CONNACK
                    return_code = response[3]
                    if return_code == 0x00:  # Connection accepted
                        self.findings.append({
                            "type": "wifi_mqtt_unauth",
                            "severity": "critical",
                            "title": "MQTT Broker Accessible Without Auth",
                            "description": f"Camera MQTT on port {port} accepts anonymous connections",
                            "target": f"{self.target}:{port}",
                            "evidence": "CONNACK with return code 0x00 (accepted)"
                        })
                        print(f"    [!] CRITICAL: MQTT open on port {port}!")

                        # Try to subscribe to all topics
                        self._test_mqtt_subscribe(sock)
                    elif return_code in (0x04, 0x05):
                        self.findings.append({
                            "type": "wifi_mqtt_exposed",
                            "severity": "medium",
                            "title": "MQTT Broker Detected",
                            "description": f"Camera runs MQTT on port {port} (auth required)",
                            "target": f"{self.target}:{port}",
                            "evidence": f"CONNACK return code: 0x{return_code:02x}"
                        })
                sock.close()
            except (socket.error, OSError):
                pass

    def _test_mqtt_subscribe(self, sock):
        """Try subscribing to wildcard MQTT topics."""
        # SUBSCRIBE to # (all topics)
        subscribe_packet = bytearray([
            0x82,  # SUBSCRIBE
            0x08,  # Remaining length
            0x00, 0x01,  # Packet ID
            0x00, 0x01,  # Topic filter length
            0x23,  # "#" (wildcard)
            0x00,  # QoS 0
        ])

        try:
            sock.send(subscribe_packet)
            response = sock.recv(4096)
            if len(response) > 0 and response[0] == 0x90:  # SUBACK
                self.findings.append({
                    "type": "wifi_mqtt_wildcard",
                    "severity": "critical",
                    "title": "MQTT Wildcard Subscribe Accepted",
                    "description": "Can subscribe to all MQTT topics - full camera control",
                    "target": self.target,
                    "evidence": "Wildcard subscription (#) accepted"
                })
        except (socket.timeout, socket.error):
            pass

    def _test_firmware_update_mitm(self):
        """Check if firmware updates use insecure channels."""
        if self.verbose:
            print("    [i] Testing firmware update security...")

        http_port = self.port or 80
        update_paths = [
            "/cgi-bin/firmware_upgrade.cgi",
            "/upgrade",
            "/api/v1/firmware/check",
            "/System/updateFirmware",
            "/ISAPI/System/updateFirmware",
            "/goform/SysToolChangePwd",
            "/cgi-bin/upgrade_firmware.cgi",
        ]

        for path in update_paths:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, http_port))

                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                sock.send(request)
                response = sock.recv(4096).decode("utf-8", errors="replace")
                sock.close()

                # If firmware endpoint is accessible over HTTP (not HTTPS)
                if "200 OK" in response or "405" in response:
                    self.findings.append({
                        "type": "wifi_firmware_insecure",
                        "severity": "high",
                        "title": "Firmware Update Over Insecure Channel",
                        "description": f"Firmware endpoint accessible via HTTP at {path}",
                        "target": f"http://{self.target}:{http_port}{path}",
                        "evidence": "Firmware update available over unencrypted HTTP - MITM possible"
                    })
                    if self.verbose:
                        print(f"    [+] Insecure firmware endpoint: {path}")
                    break
            except (socket.error, OSError):
                pass

    def _test_ap_mode_defaults(self):
        """Check for default AP mode configurations."""
        if self.verbose:
            print("    [i] Testing AP mode defaults...")

        # Many WiFi cameras create an open/default AP during setup
        # Test if AP mode config is accessible
        http_port = self.port or 80
        ap_paths = [
            "/api/v1/ap",
            "/wifi/ap_config",
            "/cgi-bin/param.cgi?cmd=getap",
            "/goform/WifiApGet",
            "/system/ap_mode",
        ]

        for path in ap_paths:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, http_port))

                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                sock.send(request)
                response = sock.recv(4096).decode("utf-8", errors="replace")
                sock.close()

                if "200 OK" in response and any(
                    x in response.lower() for x in ["ap_ssid", "ap_mode", "softap", "hotspot"]
                ):
                    self.findings.append({
                        "type": "wifi_ap_mode_exposed",
                        "severity": "high",
                        "title": "AP Mode Configuration Exposed",
                        "description": f"Camera AP mode settings accessible at {path}",
                        "target": f"http://{self.target}:{http_port}{path}",
                        "evidence": "AP mode config accessible - may allow WiFi network hijack"
                    })
                    if self.verbose:
                        print(f"    [+] AP config exposed: {path}")
            except (socket.error, OSError):
                pass

    def _test_p2p_uid_bruteforce(self):
        """Test if camera P2P UID is predictable/bruteforceable."""
        if self.verbose:
            print("    [i] Testing P2P UID predictability...")

        # Many cameras use sequential or MAC-derived UIDs
        # Check if device exposes its UID via HTTP
        http_port = self.port or 80
        uid_paths = [
            "/api/device/info",
            "/cgi-bin/magicBox.cgi?action=getSerialNo",
            "/ISAPI/System/deviceInfo",
            "/system/info",
            "/device.rsp",
        ]

        for path in uid_paths:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, http_port))

                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                sock.send(request)
                response = sock.recv(4096).decode("utf-8", errors="replace")
                sock.close()

                if "200 OK" in response:
                    body = response.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in response else ""
                    # Look for UID patterns
                    uid_patterns = [
                        r'[A-Z]{4,6}[0-9A-F]{12,20}',  # Typical P2P UID format
                        r'"uid"\s*:\s*"([^"]+)"',
                        r'"serialNumber"\s*:\s*"([^"]+)"',
                        r'"deviceId"\s*:\s*"([^"]+)"',
                    ]
                    for pattern in uid_patterns:
                        match = re.search(pattern, body)
                        if match:
                            uid = match.group(0) if not match.groups() else match.group(1)
                            self.findings.append({
                                "type": "wifi_p2p_uid_exposed",
                                "severity": "high",
                                "title": "P2P Device UID Exposed",
                                "description": f"Camera P2P UID accessible at {path}",
                                "target": f"http://{self.target}:{http_port}{path}",
                                "evidence": f"UID pattern found: {uid[:30]}..."
                            })
                            if self.verbose:
                                print(f"    [+] P2P UID exposed: {uid[:20]}...")
                            return
            except (socket.error, OSError):
                pass
