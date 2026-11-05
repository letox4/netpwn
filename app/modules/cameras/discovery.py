"""
Camera Discovery Module - Network scanning for IP cameras.
Uses common camera ports and service fingerprinting.
"""

import socket
import struct
import threading
from ipaddress import ip_network, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed


CAMERA_PORTS = [
    80, 443, 554, 8080, 8443, 8554, 8899,
    37777, 34567, 6036, 9000, 7070, 5000,
    10554, 1935, 3702, 49152
]

CAMERA_SIGNATURES = {
    b"RTSP/1.0": "RTSP Server",
    b"Hikvision": "Hikvision",
    b"Dahua": "Dahua",
    b"AXIS": "Axis",
    b"Foscam": "Foscam",
    b"Amcrest": "Amcrest",
    b"Reolink": "Reolink",
    b"TP-LINK": "TP-Link",
    b"Ubiquiti": "Ubiquiti",
    b"Vivotek": "Vivotek",
    b"Sony": "Sony Network Camera",
    b"Panasonic": "Panasonic",
    b"Samsung": "Samsung/Hanwha",
    b"Bosch": "Bosch",
    b"GeoVision": "GeoVision",
    b"D-Link": "D-Link",
    b"Wyze": "Wyze",
    b"Nest": "Google Nest",
    b"Ring": "Ring",
    b"Arlo": "Arlo",
    b"Tapo": "TP-Link Tapo",
    b"ONVIF": "ONVIF Device",
    b"IPCamera": "Generic IP Camera",
    b"webcam": "Generic Webcam",
    b"NetDVR": "Network DVR",
    b"NVR": "Network Video Recorder",
}


class CameraDiscovery:
    def __init__(self, target, timeout=3, verbose=0):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.found_cameras = []
        self.lock = threading.Lock()

    def scan(self):
        try:
            network = ip_network(self.target, strict=False)
            hosts = list(network.hosts())
        except ValueError:
            hosts = [ip_address(self.target)]

        if self.verbose:
            print(f"    [i] Scanning {len(hosts)} host(s) across {len(CAMERA_PORTS)} ports")

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for host in hosts:
                for port in CAMERA_PORTS:
                    futures.append(executor.submit(self._probe_host, str(host), port))

            for future in as_completed(futures):
                result = future.result()
                if result:
                    with self.lock:
                        self.found_cameras.append(result)

        self._onvif_discovery()
        return self.found_cameras

    def _probe_host(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))

            if result == 0:
                vendor = self._fingerprint(sock, ip, port)
                if vendor:
                    if self.verbose >= 2:
                        print(f"    [i] {ip}:{port} - {vendor}")
                    return {
                        "ip": ip,
                        "port": port,
                        "vendor": vendor,
                        "service": self._identify_service(port)
                    }
        except (socket.timeout, socket.error, OSError):
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return None

    def _fingerprint(self, sock, ip, port):
        try:
            if port == 554 or port in (8554, 10554):
                return self._rtsp_fingerprint(ip, port)

            if port in (80, 443, 8080, 8443):
                return self._http_fingerprint(ip, port)

            sock.send(b"\r\n")
            banner = sock.recv(1024)
            for sig, vendor in CAMERA_SIGNATURES.items():
                if sig.lower() in banner.lower():
                    return vendor
            if banner:
                return "Possible Camera (open port)"
        except (socket.timeout, socket.error, OSError):
            pass
        return None

    def _rtsp_fingerprint(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            request = (
                f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"User-Agent: CameraAudit/1.0\r\n"
                f"\r\n"
            ).encode()
            sock.send(request)
            response = sock.recv(2048)
            sock.close()

            if b"RTSP/1.0" in response:
                for sig, vendor in CAMERA_SIGNATURES.items():
                    if sig.lower() in response.lower():
                        return vendor
                return "RTSP Camera"
        except (socket.timeout, socket.error, OSError):
            pass
        return None

    def _http_fingerprint(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: CameraAudit/1.0\r\n"
                f"\r\n"
            ).encode()
            sock.send(request)
            response = sock.recv(4096)
            sock.close()

            response_lower = response.lower()
            for sig, vendor in CAMERA_SIGNATURES.items():
                if sig.lower() in response_lower:
                    return vendor

            camera_indicators = [
                b"camera", b"dvr", b"nvr", b"ipc",
                b"video", b"stream", b"surveillance",
                b"cgi-bin/snapshot", b"live/view"
            ]
            for indicator in camera_indicators:
                if indicator in response_lower:
                    return "Possible Camera (HTTP)"
        except (socket.timeout, socket.error, OSError):
            pass
        return None

    def _onvif_discovery(self):
        """WS-Discovery probe for ONVIF cameras."""
        try:
            probe = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"'
                ' xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
                ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"'
                ' xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
                '<e:Header>'
                '<w:MessageID>uuid:camera-audit-discovery</w:MessageID>'
                '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
                '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
                '</e:Header>'
                '<e:Body>'
                '<d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>'
                '</e:Body>'
                '</e:Envelope>'
            ).encode()

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(probe, ("239.255.255.250", 3702))

            while True:
                try:
                    data, addr = sock.recvfrom(65535)
                    ip = addr[0]
                    existing = [c for c in self.found_cameras if c["ip"] == ip]
                    if not existing:
                        self.found_cameras.append({
                            "ip": ip,
                            "port": 80,
                            "vendor": "ONVIF Device",
                            "service": "ONVIF/WS-Discovery"
                        })
                        if self.verbose:
                            print(f"    [i] ONVIF discovery: {ip}")
                except socket.timeout:
                    break
            sock.close()
        except (socket.error, OSError) as e:
            if self.verbose >= 2:
                print(f"    [i] ONVIF discovery failed: {e}")

    def _identify_service(self, port):
        services = {
            80: "HTTP", 443: "HTTPS", 554: "RTSP",
            8080: "HTTP-ALT", 8443: "HTTPS-ALT",
            8554: "RTSP-ALT", 37777: "Dahua-Binary",
            34567: "DVR-Binary", 3702: "WS-Discovery",
            1935: "RTMP", 9000: "HTTP-Management",
        }
        return services.get(port, f"TCP/{port}")
