"""
Firmware Vulnerability Checker - Detects firmware version and cross-references
with known CVE database for camera vendors.

Strategy:
1. Extract firmware/model/version from multiple endpoints (HTTP, ONVIF, vendor APIs)
2. Match against built-in CVE database
3. Compare versions to determine if vulnerable / outdated
4. Report findings with CVE IDs, CVSS scores, and remediation guidance

This module is informational - it tells the user WHICH firmware they have and
WHAT public vulnerabilities affect it.
"""

import socket
import ssl
import re
import json
import base64
from datetime import datetime


# ───────────────────────────────────────────────────────────────
# CVE Database - Curated list of well-documented camera CVEs.
# Each entry: vendor, version_pattern (regex or "<X.Y.Z" form), CVE info
# ───────────────────────────────────────────────────────────────
CVE_DATABASE = [
    # ═══ Hikvision ═══
    {
        "vendor": "hikvision",
        "affected": "<5.4.5",
        "cve": "CVE-2017-7921",
        "cvss": 10.0,
        "title": "Hikvision Authentication Bypass (Magic String)",
        "description": "Backdoor allows admin-equivalent access by appending magic string to URL",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-7921"
    },
    {
        "vendor": "hikvision",
        "affected": "<5.5.82",
        "cve": "CVE-2021-36260",
        "cvss": 9.8,
        "title": "Hikvision RCE via Web Server",
        "description": "Unauthenticated remote command injection via web server",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-36260"
    },
    {
        "vendor": "hikvision",
        "affected": "<5.6.0",
        "cve": "CVE-2022-28171",
        "cvss": 6.5,
        "title": "Hikvision Information Disclosure",
        "description": "Insufficient validation allows leakage of credentials",
        "severity": "high",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-28171"
    },

    # ═══ Dahua ═══
    {
        "vendor": "dahua",
        "affected": "<2017.04",
        "cve": "CVE-2017-7253",
        "cvss": 9.8,
        "title": "Dahua Authentication Bypass",
        "description": "DH_P2P_DETECT pattern allows unauthenticated access",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-7253"
    },
    {
        "vendor": "dahua",
        "affected": "<2.800",
        "cve": "CVE-2021-33044",
        "cvss": 9.8,
        "title": "Dahua Authentication Bypass via NetKeyboard",
        "description": "Identity authentication bypass via NetKeyboard protocol",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-33044"
    },
    {
        "vendor": "dahua",
        "affected": "<2.800",
        "cve": "CVE-2021-33045",
        "cvss": 9.8,
        "title": "Dahua Authentication Bypass via Loopback",
        "description": "Identity authentication bypass via construction of malicious data packets",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-33045"
    },

    # ═══ Axis ═══
    {
        "vendor": "axis",
        "affected": "<8.50.1",
        "cve": "CVE-2018-10661",
        "cvss": 7.5,
        "title": "Axis Authentication Bypass",
        "description": "Auth bypass through authorization bypass",
        "severity": "high",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-10661"
    },
    {
        "vendor": "axis",
        "affected": "<8.50.1",
        "cve": "CVE-2018-10662",
        "cvss": 8.8,
        "title": "Axis Exposed Insecure Interface",
        "description": "Internal interface exposed via .srv endpoint",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-10662"
    },
    {
        "vendor": "axis",
        "affected": "<8.50.1",
        "cve": "CVE-2018-10663",
        "cvss": 5.3,
        "title": "Axis Memory Disclosure",
        "description": "Memory leak via crafted requests",
        "severity": "medium",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-10663"
    },

    # ═══ Foscam ═══
    {
        "vendor": "foscam",
        "affected": "<2.81.1.119",
        "cve": "CVE-2018-19069",
        "cvss": 9.8,
        "title": "Foscam Stack Buffer Overflow",
        "description": "Stack-based buffer overflow in Foscam web server",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-19069"
    },
    {
        "vendor": "foscam",
        "affected": "<2.x",
        "cve": "CVE-2017-2841",
        "cvss": 9.8,
        "title": "Foscam Hardcoded Credentials",
        "description": "Hardcoded credentials allow remote access",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-2841"
    },

    # ═══ Reolink ═══
    {
        "vendor": "reolink",
        "affected": "<v3.0.0.136_20121102",
        "cve": "CVE-2020-25169",
        "cvss": 7.5,
        "title": "Reolink Camera Information Disclosure",
        "description": "Unauthenticated info disclosure via API",
        "severity": "high",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-25169"
    },

    # ═══ Wyze ═══
    {
        "vendor": "wyze",
        "affected": "<4.36.x",
        "cve": "CVE-2019-9564",
        "cvss": 9.8,
        "title": "Wyze Cam Authentication Bypass",
        "description": "Auth bypass allows takeover of Wyze cameras",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-9564"
    },
    {
        "vendor": "wyze",
        "affected": "<4.36.0.x",
        "cve": "CVE-2019-12266",
        "cvss": 7.5,
        "title": "Wyze Cam Stack Buffer Overflow",
        "description": "RCE via crafted UDP packets to camera",
        "severity": "high",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-12266"
    },

    # ═══ TP-Link Tapo ═══
    {
        "vendor": "tapo",
        "affected": "<1.1.15",
        "cve": "CVE-2023-27620",
        "cvss": 9.8,
        "title": "Tapo C200 Authentication Bypass",
        "description": "Auth bypass in passthrough mode allows full takeover",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2023-27620"
    },

    # ═══ Eufy ═══
    {
        "vendor": "eufy",
        "affected": "<2.2.x",
        "cve": "CVE-2023-23576",
        "cvss": 6.5,
        "title": "Eufy Stream Privacy Issue",
        "description": "RTSP streams accessible without authentication contradicting E2E claims",
        "severity": "high",
        "ref": "https://www.theverge.com/2023/2/1/23582617/eufy-anker-camera-cloud-encryption-investigation"
    },

    # ═══ Generic / SDK ═══
    {
        "vendor": "ilnkp2p",
        "affected": "*",
        "cve": "CVE-2019-11219",
        "cvss": 9.1,
        "title": "iLnkP2P Information Disclosure",
        "description": "P2P protocol leaks device IDs and allows remote takeover",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-11219"
    },
    {
        "vendor": "tutk",
        "affected": "<3.1.10",
        "cve": "CVE-2021-28372",
        "cvss": 9.1,
        "title": "TUTK Kalay P2P Authentication Bypass",
        "description": "Auth bypass allows hijacking of camera connections",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-28372"
    },
    {
        "vendor": "thoughroughtek",
        "affected": "<3.1.10",
        "cve": "CVE-2021-32934",
        "cvss": 9.1,
        "title": "TUTK SDK Insufficient Authentication",
        "description": "Audio/video stream interception possible",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-32934"
    },

    # ═══ D-Link ═══
    {
        "vendor": "dlink",
        "affected": "<v1.04",
        "cve": "CVE-2019-10999",
        "cvss": 9.8,
        "title": "D-Link Stack Buffer Overflow",
        "description": "Stack overflow in DCS-825L allows RCE",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-10999"
    },

    # ═══ Xiongmai/XMEye ═══
    {
        "vendor": "xiongmai",
        "affected": "*",
        "cve": "CVE-2018-10676",
        "cvss": 9.8,
        "title": "Xiongmai/XMEye Default Credentials",
        "description": "Hardcoded backdoor credentials in firmware",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-10676"
    },

    # ═══ Generic ONVIF ═══
    {
        "vendor": "onvif",
        "affected": "*",
        "cve": "CVE-2019-7256",
        "cvss": 9.8,
        "title": "ONVIF Generic Authentication Bypass",
        "description": "Multiple ONVIF implementations missing auth on critical endpoints",
        "severity": "critical",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-7256"
    },
]


class FirmwareVulnChecker:
    def __init__(self, target, port=None, timeout=5, verbose=0):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.findings = []
        self.detected = {
            "vendor": None,
            "model": None,
            "firmware": None,
            "build_date": None,
            "device_type": None,
        }

    def run(self):
        # Step 1: Try to detect firmware version
        self._detect_via_http_banners()
        self._detect_via_onvif()
        self._detect_via_hikvision()
        self._detect_via_dahua()
        self._detect_via_axis()
        self._detect_via_reolink()
        self._detect_via_wyze()
        self._detect_via_tapo()
        self._detect_via_xmeye()

        # Step 2: Report what was detected
        if any(self.detected.values()):
            self.findings.append({
                "type": "firmware_detected",
                "severity": "info",
                "title": "Firmware Information Detected",
                "description": "Camera firmware/model identified",
                "target": self.target,
                "evidence": {k: v for k, v in self.detected.items() if v}
            })
            if self.verbose:
                print(f"    [+] Detected: {self.detected}")

        # Step 3: Cross-reference with CVE DB
        self._check_cves()

        return self.findings

    # ───────────────────────────────────────────────────────────
    # Detection methods (each tries one vendor/protocol)
    # ───────────────────────────────────────────────────────────

    def _http_get(self, path, port=80, use_ssl=False, headers=None,
                  method="GET", body=None):
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

            req = f"{method} {path} HTTP/1.1\r\n"
            req += f"Host: {self.target}\r\n"
            req += "User-Agent: CameraAudit/1.0\r\n"
            req += "Connection: close\r\n"
            if headers:
                for k, v in headers.items():
                    req += f"{k}: {v}\r\n"
            if body:
                req += f"Content-Length: {len(body)}\r\n\r\n"
                full = req.encode() + body
            else:
                req += "\r\n"
                full = req.encode()

            sock.send(full)
            resp = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 65536:
                        break
                except socket.timeout:
                    break
            sock.close()
            return resp.decode("utf-8", errors="replace")
        except (socket.error, ssl.SSLError, OSError):
            return None

    def _detect_via_http_banners(self):
        """Generic HTTP server banner / vendor strings."""
        if self.verbose:
            print("    [i] Checking HTTP banners for firmware info...")

        for port in [80, 443, 8080, 8443]:
            use_ssl = port in (443, 8443)
            resp = self._http_get("/", port=port, use_ssl=use_ssl)
            if not resp:
                continue

            lines = resp.split("\r\n")
            # Server header
            for line in lines:
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    self._parse_server_header(server)
                    break

            # Vendor strings in body
            body = resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""
            self._parse_body_signatures(body)

    def _parse_server_header(self, server):
        """Parse Server: header for version info."""
        # webs/, lighttpd/, etc.
        m = re.search(r"App-webs/(\d+\.\d+(?:\.\d+)?)", server)
        if m:
            self.detected["firmware"] = m.group(1)

        # Hikvision DNVRS-Webs
        if "DNVRS" in server or "DVRDVS" in server:
            self.detected["vendor"] = self.detected["vendor"] or "hikvision"

        # Custom embedded servers
        m = re.search(r"(\w+)/(\d+\.\d+(?:\.\d+)?)", server)
        if m and not self.detected["firmware"]:
            self.detected["firmware"] = m.group(2)

    def _parse_body_signatures(self, body):
        """Look for vendor signatures in HTML body."""
        body_lower = body.lower()
        signatures = {
            "hikvision": ["hikvision", "ipcamera", "/doc/page/"],
            "dahua": ["dahua", "magicbox.cgi"],
            "axis": ["axis", "axis-cgi"],
            "foscam": ["foscam", "cgiproxy.fcgi"],
            "reolink": ["reolink"],
            "wyze": ["wyze"],
            "tapo": ["tapo", "tp-link"],
            "eufy": ["eufy", "anker"],
            "amcrest": ["amcrest"],
            "vivotek": ["vivotek"],
            "samsung": ["samsung", "hanwha"],
            "uniview": ["uniview", "lapi"],
            "xiongmai": ["xmeye", "xiongmai", "netsurveillance"],
        }

        for vendor, sigs in signatures.items():
            if any(s in body_lower for s in sigs):
                if not self.detected["vendor"]:
                    self.detected["vendor"] = vendor

        # Try to extract version from common patterns
        version_patterns = [
            r"firmware[:\s]+v?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)",
            r"version[:\s]+v?(\d+\.\d+(?:\.\d+)?)",
            r"build[:\s]+(\d{4}\d{2}\d{2})",
        ]
        for pattern in version_patterns:
            m = re.search(pattern, body, re.IGNORECASE)
            if m and not self.detected["firmware"]:
                self.detected["firmware"] = m.group(1)
                break

    def _detect_via_onvif(self):
        """ONVIF GetDeviceInformation (often unauthenticated)."""
        if self.verbose:
            print("    [i] Trying ONVIF GetDeviceInformation...")

        envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
            '<s:Body><tds:GetDeviceInformation/></s:Body>'
            '</s:Envelope>'
        ).encode()

        for port in [80, 8080, 443, 8443]:
            for path in ["/onvif/device_service", "/onvif/Device", "/Device"]:
                resp = self._http_get(
                    path, port=port,
                    use_ssl=(port in (443, 8443)),
                    method="POST", body=envelope,
                    headers={"Content-Type": "application/soap+xml"}
                )
                if not resp or "200 OK" not in resp.split("\r\n")[0]:
                    continue

                body = resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

                # Parse SOAP response
                m = re.search(r"<tds:Manufacturer[^>]*>([^<]+)</tds:Manufacturer>", body)
                if m:
                    self.detected["vendor"] = m.group(1).lower().strip()

                m = re.search(r"<tds:Model[^>]*>([^<]+)</tds:Model>", body)
                if m:
                    self.detected["model"] = m.group(1).strip()

                m = re.search(r"<tds:FirmwareVersion[^>]*>([^<]+)</tds:FirmwareVersion>", body)
                if m:
                    self.detected["firmware"] = m.group(1).strip()

                if self.detected["vendor"]:
                    if self.verbose:
                        print(f"    [+] ONVIF: {self.detected}")
                    return

    def _detect_via_hikvision(self):
        """Hikvision-specific endpoints."""
        endpoints = [
            "/ISAPI/System/deviceInfo",
            "/System/deviceInfo",
        ]
        for ep in endpoints:
            for auth_header in [None, {"Authorization": "Basic YWRtaW46MTIzNDU="}]:
                resp = self._http_get(ep, port=80, headers=auth_header)
                if resp and "200 OK" in resp.split("\r\n")[0]:
                    body = resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

                    m = re.search(r"<firmwareVersion[^>]*>([^<]+)</firmwareVersion>", body)
                    if m:
                        self.detected["firmware"] = m.group(1).strip()
                        self.detected["vendor"] = "hikvision"

                    m = re.search(r"<model[^>]*>([^<]+)</model>", body)
                    if m:
                        self.detected["model"] = m.group(1).strip()

                    m = re.search(r"<firmwareReleasedDate[^>]*>([^<]+)</firmwareReleasedDate>", body)
                    if m:
                        self.detected["build_date"] = m.group(1).strip()

                    if self.detected["firmware"]:
                        return

    def _detect_via_dahua(self):
        """Dahua magicBox.cgi endpoints."""
        endpoints = [
            "/cgi-bin/magicBox.cgi?action=getSystemInfo",
            "/cgi-bin/magicBox.cgi?action=getSoftwareVersion",
            "/cgi-bin/magicBox.cgi?action=getDeviceType",
        ]
        for ep in endpoints:
            resp = self._http_get(ep, port=80)
            if resp and "200 OK" in resp.split("\r\n")[0]:
                body = resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

                if "magicBox.cgi" in ep or "version" in body.lower():
                    self.detected["vendor"] = "dahua"

                m = re.search(r"version=([^\r\n;]+)", body, re.IGNORECASE)
                if m:
                    self.detected["firmware"] = m.group(1).strip()

                m = re.search(r"deviceType=([^\r\n;]+)", body, re.IGNORECASE)
                if m:
                    self.detected["model"] = m.group(1).strip()

                m = re.search(r"BuildDate=([^\r\n;]+)", body, re.IGNORECASE)
                if m:
                    self.detected["build_date"] = m.group(1).strip()

    def _detect_via_axis(self):
        """Axis-specific param.cgi."""
        resp = self._http_get(
            "/axis-cgi/param.cgi?action=list&group=Properties.Firmware",
            port=80
        )
        if resp and "200 OK" in resp.split("\r\n")[0]:
            body = resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""
            m = re.search(r"Firmware\.Version=([^\r\n]+)", body)
            if m:
                self.detected["firmware"] = m.group(1).strip()
                self.detected["vendor"] = "axis"

    def _detect_via_reolink(self):
        """Reolink local API."""
        body_data = json.dumps([{"cmd": "GetDevInfo", "action": 0,
                                 "param": {}}]).encode()
        resp = self._http_get(
            "/cgi-bin/api.cgi?cmd=GetDevInfo", port=80,
            method="POST", body=body_data
        )
        if resp and "200 OK" in resp.split("\r\n")[0]:
            body = resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""
            try:
                data = json.loads(body)
                if isinstance(data, list) and data:
                    val = data[0].get("value", {}).get("DevInfo", {})
                    self.detected["vendor"] = "reolink"
                    self.detected["firmware"] = val.get("firmVer")
                    self.detected["model"] = val.get("model")
                    self.detected["build_date"] = val.get("buildDay")
            except (json.JSONDecodeError, KeyError, AttributeError):
                pass

    def _detect_via_wyze(self):
        """Wyze RTSP firmware fingerprint."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, 554))
            req = (
                f"OPTIONS rtsp://{self.target}:554/ RTSP/1.0\r\n"
                f"CSeq: 1\r\nUser-Agent: WyzeApp\r\n\r\n"
            ).encode()
            sock.send(req)
            resp = sock.recv(2048)
            sock.close()

            if b"WyzeCam" in resp or b"wyze" in resp.lower():
                self.detected["vendor"] = "wyze"
                m = re.search(rb"WyzeCam/([\d.]+)", resp)
                if m:
                    self.detected["firmware"] = m.group(1).decode()
        except (socket.error, OSError):
            pass

    def _detect_via_tapo(self):
        """Tapo handshake1 detection."""
        body = b'{"method":"handshake","params":{}}'
        resp = self._http_get("/app/handshake1", port=443,
                              use_ssl=True, method="POST", body=body)
        if resp and "200" in resp.split("\r\n")[0]:
            self.detected["vendor"] = "tapo"

        # Try to get version via component_negotiate (sometimes unauth-able)
        body = b'{"method":"component_negotiate"}'
        resp = self._http_get("/app", port=443,
                              use_ssl=True, method="POST", body=body)
        if resp:
            body_resp = resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""
            m = re.search(r'"fw_ver"\s*:\s*"([^"]+)"', body_resp)
            if m:
                self.detected["firmware"] = m.group(1)

    def _detect_via_xmeye(self):
        """XMEye/Xiongmai binary protocol fingerprint."""
        try:
            import struct
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if sock.connect_ex((self.target, 34567)) != 0:
                sock.close()
                return

            # Login query - just looking for response signature
            login = json.dumps({"EncryptType": "MD5", "LoginType": "DVRIP-Web",
                                "PassWord": "", "UserName": "test"}).encode()
            header = struct.pack("<BBHI", 0xFF, 0x01, 0, 0)
            header += struct.pack("<III", 0, 1, 0x3E8)
            header += struct.pack("<I", len(login))
            sock.send(header + login)
            resp = sock.recv(4096)
            sock.close()

            if len(resp) > 20 and resp[0] == 0xFF:
                self.detected["vendor"] = "xiongmai"
        except (socket.error, OSError):
            pass

    # ───────────────────────────────────────────────────────────
    # CVE matching
    # ───────────────────────────────────────────────────────────

    def _check_cves(self):
        """Cross-reference detected info with CVE DB."""
        vendor = (self.detected.get("vendor") or "").lower().strip()
        firmware = self.detected.get("firmware") or ""

        if not vendor:
            self.findings.append({
                "type": "firmware_no_vendor",
                "severity": "info",
                "title": "Could Not Identify Vendor",
                "description": "Insufficient information to check CVEs",
                "target": self.target,
                "evidence": "Run with --discover or --modern first"
            })
            return

        applicable_cves = []
        for entry in CVE_DATABASE:
            if entry["vendor"] not in vendor and vendor not in entry["vendor"]:
                continue

            # Check version
            if entry["affected"] == "*":
                applicable_cves.append(entry)
                continue

            if firmware and self._version_matches(firmware, entry["affected"]):
                applicable_cves.append(entry)
            elif not firmware:
                # Cannot determine version - flag as potentially applicable
                applicable_cves.append({**entry, "_uncertain": True})

        if not applicable_cves:
            self.findings.append({
                "type": "firmware_no_known_cves",
                "severity": "info",
                "title": f"No Known CVEs Match: {vendor}",
                "description": f"Detected vendor {vendor} has no matching CVEs in DB",
                "target": self.target,
                "evidence": {
                    "vendor": vendor,
                    "firmware": firmware or "unknown",
                    "db_size": len(CVE_DATABASE)
                }
            })
            return

        # Generate one finding per applicable CVE
        for cve in applicable_cves:
            uncertain = cve.get("_uncertain", False)
            severity = "info" if uncertain else cve["severity"]
            title = cve["title"]
            if uncertain:
                title = f"[POSSIBLE] {title} (version unknown)"

            self.findings.append({
                "type": f"cve_{cve['cve'].lower().replace('-', '_')}",
                "severity": severity,
                "title": title,
                "description": cve["description"],
                "target": self.target,
                "evidence": {
                    "cve_id": cve["cve"],
                    "cvss_score": cve["cvss"],
                    "vendor": vendor,
                    "detected_firmware": firmware or "unknown",
                    "affected_versions": cve["affected"],
                    "reference": cve["ref"],
                    "uncertain_match": uncertain,
                }
            })
            if not uncertain and self.verbose:
                print(f"    [!] {severity.upper()}: {cve['cve']} - {cve['title']}")

        # Summary
        critical_count = sum(1 for c in applicable_cves
                            if c.get("severity") == "critical"
                            and not c.get("_uncertain"))
        if critical_count > 0:
            print(f"    [!] {critical_count} CRITICAL CVE(s) match this firmware")

    def _version_matches(self, detected, affected_spec):
        """Check if detected version matches affected version spec."""
        if affected_spec == "*":
            return True

        # "<X.Y.Z" form
        m = re.match(r"<\s*v?(\S+)", affected_spec)
        if m:
            target = m.group(1)
            return self._version_lt(detected, target)

        # ">X.Y.Z" form
        m = re.match(r">\s*v?(\S+)", affected_spec)
        if m:
            target = m.group(1)
            return self._version_lt(target, detected)

        # Exact match
        return detected == affected_spec or detected.startswith(affected_spec)

    def _version_lt(self, version_a, version_b):
        """Returns True if version_a < version_b."""
        try:
            # Strip leading 'v', dates handled separately
            va = re.sub(r"[^\d.]", "", version_a).strip(".")
            vb = re.sub(r"[^\d.]", "", version_b).strip(".")

            if not va or not vb:
                return False

            parts_a = [int(x) for x in va.split(".") if x.isdigit()]
            parts_b = [int(x) for x in vb.split(".") if x.isdigit()]

            # Pad with zeros
            max_len = max(len(parts_a), len(parts_b))
            parts_a += [0] * (max_len - len(parts_a))
            parts_b += [0] * (max_len - len(parts_b))

            return parts_a < parts_b
        except (ValueError, AttributeError):
            return False
