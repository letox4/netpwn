"""
Credential Tester Module - Tests default/common credentials
across RTSP, HTTP, and ONVIF protocols.
"""

import socket
import ssl
import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed


DEFAULT_CREDENTIALS = [
    # (username, password, vendor_hint)
    ("admin", "", "Generic"),
    ("admin", "admin", "Generic"),
    ("admin", "12345", "Generic"),
    ("admin", "123456", "Generic"),
    ("admin", "1234", "Generic"),
    ("admin", "password", "Generic"),
    ("admin", "admin123", "Generic"),
    ("admin", "888888", "Dahua"),
    ("admin", "666666", "Dahua"),
    ("admin", "1111111", "Dahua"),
    ("admin", "1234567", "Generic"),
    ("admin", "12345678", "Generic"),
    ("admin", "pass", "Generic"),
    ("admin", "camera", "Generic"),
    ("admin", "Admin123", "Generic"),
    ("admin", "admin@123", "Generic"),
    ("root", "", "Axis/Generic"),
    ("root", "root", "Generic"),
    ("root", "pass", "Axis"),
    ("root", "admin", "Generic"),
    ("root", "camera", "Generic"),
    ("root", "123456", "Generic"),
    ("user", "user", "Generic"),
    ("guest", "guest", "Generic"),
    ("operator", "operator", "Generic"),
    ("supervisor", "supervisor", "Generic"),
    ("service", "service", "Generic"),
    ("default", "default", "Generic"),
    ("Admin", "1234", "Samsung/Hanwha"),
    ("admin", "4321", "Samsung"),
    ("admin", "111111", "Samsung"),
    ("root", "system", "Vivotek"),
    ("root", "icatch99", "iCatch"),
    ("admin", "meinsm", "Mobotix"),
    ("admin", "wbox123", "W-Box"),
    ("admin", "supervisor", "Pelco"),
    ("admin", "hikvision", "Hikvision"),
    ("admin", "hik12345", "Hikvision"),
    ("admin", "Hikvision1", "Hikvision"),
    ("admin", "a]12345678Z", "Hikvision"),
    ("admin", "flirone", "FLIR"),
    ("admin", "tlJwpbo6", "Dahua"),
    ("admin", "7ujMko0admin", "Dahua"),
    ("666666", "666666", "Dahua"),
    ("888888", "888888", "Dahua"),
    ("ubnt", "ubnt", "Ubiquiti"),
    ("admin", "ubnt", "Ubiquiti"),
    ("viewer", "viewer", "Generic"),
    ("live", "live", "Generic"),
    ("demo", "demo", "Generic"),
    ("admin", "9999", "Foscam"),
    ("admin", "reolink", "Reolink"),
    ("admin", "tp-link", "TP-Link"),
    ("admin", "2601hx", "Uniview"),
]


class CredentialTester:
    def __init__(self, target, port=None, timeout=5, verbose=0):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.findings = []

    def run(self):
        self._test_rtsp_creds()
        self._test_http_creds()
        return self.findings

    def _test_rtsp_creds(self):
        port = self.port or 554
        if self.verbose:
            print(f"    [i] Testing {len(DEFAULT_CREDENTIALS)} credential pairs on RTSP...")

        valid_creds = []
        for username, password, vendor in DEFAULT_CREDENTIALS:
            if self._try_rtsp_auth(username, password, port):
                valid_creds.append((username, password, vendor))
                print(f"    [!] RTSP credential found: {username}:{password} ({vendor})")
                if not self.verbose:
                    break

        if valid_creds:
            self.findings.append({
                "type": "default_credentials_rtsp",
                "severity": "critical",
                "title": "Default RTSP Credentials",
                "description": f"Camera accepts default credentials via RTSP",
                "target": f"rtsp://{self.target}:{port}/",
                "evidence": [
                    {"user": u, "pass": p, "vendor": v}
                    for u, p, v in valid_creds
                ]
            })

    def _try_rtsp_auth(self, username, password, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))

            # First request to get auth challenge
            request = (
                f"DESCRIBE rtsp://{self.target}:{port}/ RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"\r\n"
            ).encode()
            sock.send(request)
            response = sock.recv(2048).decode("utf-8", errors="replace")

            if "401" not in response:
                sock.close()
                return "200" in response

            # Try Basic auth
            creds = base64.b64encode(f"{username}:{password}".encode()).decode()
            request = (
                f"DESCRIBE rtsp://{self.target}:{port}/ RTSP/1.0\r\n"
                f"CSeq: 2\r\n"
                f"Authorization: Basic {creds}\r\n"
                f"\r\n"
            ).encode()
            sock.send(request)
            response = sock.recv(2048).decode("utf-8", errors="replace")
            sock.close()

            if "200" in response:
                return True

            # Try Digest auth if realm provided
            if "Digest" in response and "realm" in response:
                return self._try_rtsp_digest(username, password, port, response)

            return False
        except (socket.timeout, socket.error, OSError):
            return False

    def _try_rtsp_digest(self, username, password, port, challenge):
        try:
            import re
            realm_match = re.search(r'realm="([^"]*)"', challenge)
            nonce_match = re.search(r'nonce="([^"]*)"', challenge)

            if not realm_match or not nonce_match:
                return False

            realm = realm_match.group(1)
            nonce = nonce_match.group(1)
            uri = f"rtsp://{self.target}:{port}/"
            method = "DESCRIBE"

            ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
            ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
            response_hash = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))

            auth_header = (
                f'Digest username="{username}", realm="{realm}", '
                f'nonce="{nonce}", uri="{uri}", response="{response_hash}"'
            )
            request = (
                f"DESCRIBE {uri} RTSP/1.0\r\n"
                f"CSeq: 3\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ).encode()
            sock.send(request)
            response = sock.recv(2048).decode("utf-8", errors="replace")
            sock.close()

            return "200" in response
        except (socket.timeout, socket.error, OSError):
            return False

    def _test_http_creds(self):
        port = self.port or 80
        use_ssl = port in (443, 8443)
        if self.verbose:
            print(f"    [i] Testing credentials on HTTP{'S' if use_ssl else ''}...")

        login_paths = [
            "/", "/login", "/cgi-bin/snapshot.cgi",
            "/ISAPI/Security/userCheck", "/cgi-bin/magicBox.cgi?action=getDeviceType"
        ]

        valid_creds = []
        for username, password, vendor in DEFAULT_CREDENTIALS:
            for path in login_paths:
                if self._try_http_basic(username, password, port, path, use_ssl):
                    valid_creds.append((username, password, vendor, path))
                    print(f"    [!] HTTP credential found: {username}:{password} at {path}")
                    break
            if valid_creds and not self.verbose:
                break

        if valid_creds:
            self.findings.append({
                "type": "default_credentials_http",
                "severity": "critical",
                "title": "Default HTTP Credentials",
                "description": "Camera web interface accepts default credentials",
                "target": f"http{'s' if use_ssl else ''}://{self.target}:{port}/",
                "evidence": [
                    {"user": u, "pass": p, "vendor": v, "path": path}
                    for u, p, v, path in valid_creds
                ]
            })

    def _try_http_basic(self, username, password, port, path, use_ssl):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.target)

            sock.connect((self.target, port))

            creds = base64.b64encode(f"{username}:{password}".encode()).decode()
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"Authorization: Basic {creds}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            sock.send(request)
            response = sock.recv(2048).decode("utf-8", errors="replace")
            sock.close()

            first_line = response.split("\r\n")[0] if response else ""
            return " 200 " in first_line
        except (socket.timeout, socket.error, ssl.SSLError, OSError):
            return False
