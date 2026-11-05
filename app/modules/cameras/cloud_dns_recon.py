"""
Cloud DNS Reconnaissance - Maps the cloud infrastructure of camera vendors.

For modern cameras with cloud-only architecture, this enumerates and
classifies vendor cloud infrastructure with multi-layer validation:

    DNS resolves
        ↓
    Is IP public? ─── No ──→ DISCARD (false positive guaranteed)
        ↓ Yes
    Responds HTTP/HTTPS? ─── No ──→ INFO (DNS-only, no service)
        ↓ Yes
    Same IP as production? ─── Yes ──→ INFO (alias / CDN)
        ↓ No
    Status 200 without auth? ──→ MEDIUM
    Exposes /docs, /swagger, errors? ──→ HIGH
    Only 401/403? ──→ LOW (exists but protected)

Non-intrusive: only DNS + HTTP HEAD/GET + TLS handshakes.
"""

import socket
import ssl
import struct
import re
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


# Comprehensive vendor cloud domain map
VENDOR_DOMAINS = {
    "eufy": [
        "security-app.eufylife.com",
        "mysecurity.eufylife.com",
        "p2p-prd.eufylife.com",
        "ms.eufylife.com",
        "register2.eufylife.com",
        "passport.eufylife.com",
        "auth.eufylife.com",
        "openapi.eufylife.com",
        "rt.eufylife.com",
    ],
    "wyze": [
        "api.wyzecam.com",
        "auth-prod.api.wyze.com",
        "wyze-mqtt.wyzecam.com",
        "wyze-monitor.wyzecam.com",
        "wyze-events.wyzecam.com",
        "wyze-thumbnails.s3.amazonaws.com",
    ],
    "tapo": [
        "wap.tplinkcloud.com",
        "n-eu-wap.tplinkcloud.com",
        "use1-wap.tplinkcloud.com",
        "n-device-api.tplinkcloud.com",
        "aps1-wap.tplinkcloud.com",
        "euw1-app-server.iot.i.tplinknbu.com",
    ],
    "ring": [
        "api.ring.com",
        "fw.ring.com",
        "oauth.ring.com",
        "app.ring.com",
        "media.ring.com",
        "events.ring.com",
        "deviceupdates.ring.com",
        "device.ring.com",
    ],
    "arlo": [
        "my.arlo.com",
        "myapi.arlo.com",
        "ocapi-app.arlo.com",
        "arlo-cms-prod-1.s3.amazonaws.com",
        "ng-streamer-1.arlo.com",
    ],
    "nest": [
        "nexus.dropcam.com",
        "home.nest.com",
        "nestlabs.com",
        "nestapi.com",
        "transport.home.nest.com",
        "weave.nestlabs.com",
    ],
    "blink": [
        "rest-prod.immedia-semi.com",
        "rest-u034.immedia-semi.com",
        "rest-u012.immedia-semi.com",
        "video.immedia-semi.com",
    ],
    "reolink": [
        "home.reolink.com",
        "p2p.reolink.com",
        "p2p1.reolink.com",
        "p2p2.reolink.com",
        "downloads.reolink.com",
        "apis.reolink.com",
    ],
    "imou": [
        "openapi.easy4ip.com",
        "p2p.easy4ip.com",
        "icc.imoulife.com",
    ],
    "tutk_kalay": [
        "p2p.tutk.com",
        "p2p1.tutk.com",
        "p2p2.tutk.com",
        "m2.tutk.com",
        "iotcplatform.com",
        "d.iotcplatform.com",
    ],
    "tuya": [
        "a1.tuyacn.com",
        "a1.tuyaus.com",
        "a1.tuyaeu.com",
        "openapi.tuyacn.com",
        "openapi.tuyaus.com",
        "openapi.tuyaeu.com",
        "m1.tuyacn.com",
    ],
}

# Subdomain patterns to bruteforce
SUBDOMAIN_WORDLIST = [
    "api", "api-prod", "api-staging", "api-dev",
    "auth", "oauth", "sso", "login",
    "p2p", "p2p-prd", "p2p-stage",
    "media", "stream", "video", "cdn", "static",
    "mqtt", "ws", "websocket",
    "push", "fcm", "notify",
    "fw", "firmware", "ota", "update",
    "cms", "admin", "config",
    "events", "logs", "metrics",
    "test", "qa", "staging", "dev", "internal",
    "old", "legacy", "v1", "v2", "v3",
    "device", "devices",
    "thumbnails", "snapshots", "backup",
]

# Cloud provider IP ranges (simplified detection)
CLOUD_PROVIDERS = {
    "AWS": ["52.", "54.", "3.", "13.", "18.", "34.", "35.", "44.", "50.",
            "75.", "99.", "107.", "172.", "174.", "184.", "204.", "207."],
    "GCP": ["35.190.", "35.191.", "35.224.", "34.64.", "34.96.", "34.118."],
    "Azure": ["13.64.", "13.65.", "13.66.", "20.", "40.", "104.", "168.61."],
    "Cloudflare": ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
                   "104.21.", "104.22.", "172.64.", "172.65.", "172.66.",
                   "172.67."],
    "Akamai": ["23.", "104.96.", "104.97.", "104.98.", "104.99.",
               "184.84.", "184.85.", "184.86.", "184.87."],
}

# Sensitive paths that indicate over-exposure when accessible
SENSITIVE_PATHS = [
    ("/swagger", "API documentation"),
    ("/swagger-ui/", "Swagger UI"),
    ("/swagger-ui.html", "Swagger UI"),
    ("/api-docs", "API docs"),
    ("/v2/api-docs", "OpenAPI v2 docs"),
    ("/v3/api-docs", "OpenAPI v3 docs"),
    ("/openapi.json", "OpenAPI spec"),
    ("/openapi.yaml", "OpenAPI spec"),
    ("/graphql", "GraphQL endpoint"),
    ("/graphiql", "GraphiQL playground"),
    ("/.env", "Environment file"),
    ("/.git/config", "Git config exposure"),
    ("/actuator", "Spring Actuator"),
    ("/actuator/env", "Spring env"),
    ("/actuator/health", "Spring health"),
    ("/server-status", "Apache server-status"),
    ("/server-info", "Apache server-info"),
    ("/phpinfo.php", "PHP info"),
    ("/info.php", "PHP info"),
    ("/admin/", "Admin panel"),
    ("/console", "Console (Spring/Vaadin)"),
    ("/debug", "Debug endpoint"),
    ("/_profiler/", "Symfony profiler"),
]

# Headers that reveal environment
DEV_INDICATOR_HEADERS = [
    "x-environment", "x-env", "x-stage", "x-staging",
    "x-debug", "x-debug-mode",
]


class CloudDNSRecon:
    def __init__(self, target=None, vendor=None, timeout=5, verbose=0):
        self.target = target
        self.vendor = vendor
        self.timeout = timeout
        self.verbose = verbose
        self.findings = []

        # Cache to avoid duplicate HTTP probes
        self._http_cache = {}
        # Production IP per vendor (for alias detection)
        self._prod_ips = {}

    def run(self):
        if self.vendor:
            vendors_to_scan = [self.vendor] if self.vendor in VENDOR_DOMAINS else []
        else:
            vendors_to_scan = list(VENDOR_DOMAINS.keys())

        for vendor in vendors_to_scan:
            self._scan_vendor(vendor)

        return self.findings

    def _scan_vendor(self, vendor):
        if self.verbose:
            print(f"    [i] Cloud recon for vendor: {vendor}")

        domains = VENDOR_DOMAINS[vendor]
        resolved = {}
        cloud_providers_seen = set()

        # Resolve all base domains, track production IPs
        prod_ips = set()
        for domain in domains:
            ip = self._resolve(domain)
            if not ip:
                continue
            resolved[domain] = ip

            # Skip non-public IPs entirely (false positives)
            if not self._is_public_ip(ip):
                if self.verbose >= 2:
                    print(f"    [skip] {domain} -> {ip} (private/reserved)")
                continue

            prod_ips.add(ip)
            provider = self._identify_cloud_provider(ip)
            if provider:
                cloud_providers_seen.add(provider)

            if self.verbose >= 2:
                print(f"    [+] {domain} -> {ip} ({provider or 'Unknown'})")

        self._prod_ips[vendor] = prod_ips

        if not resolved:
            return

        # Subdomain bruteforce on first 2 base domains
        for base_domain in domains[:2]:
            self._subdomain_brute(base_domain, resolved, vendor)

        # TLS cert analysis on key endpoints
        for domain, ip in list(resolved.items())[:5]:
            if self._is_public_ip(ip):
                self._analyze_cert(domain, ip)

        # Save vendor recon summary (only public IPs counted)
        public_resolved = {d: i for d, i in resolved.items()
                          if self._is_public_ip(i)}
        if public_resolved:
            self.findings.append({
                "type": "cloud_recon_vendor",
                "severity": "info",
                "title": f"Cloud Infrastructure: {vendor.upper()}",
                "description": f"Mapped {len(public_resolved)} public domain(s) for {vendor}",
                "target": vendor,
                "evidence": {
                    "domains_resolved": public_resolved,
                    "cloud_providers": list(cloud_providers_seen),
                    "domain_count": len(public_resolved),
                }
            })

        if self.verbose:
            print(f"    [+] {vendor}: {len(public_resolved)} public domains "
                  f"on {cloud_providers_seen}")

    # ───────────────────────────────────────────────────────────
    # IP classification
    # ───────────────────────────────────────────────────────────
    def _is_public_ip(self, ip_str):
        """Filter out private/reserved IPs (loopback, RFC1918, link-local, etc.)"""
        if not ip_str:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
        except (ValueError, TypeError):
            return False

        # Exclude all private/reserved ranges
        if ip.is_private:           # 10/8, 172.16/12, 192.168/16, 100.64/10
            return False
        if ip.is_loopback:          # 127.0.0.0/8
            return False
        if ip.is_link_local:        # 169.254/16
            return False
        if ip.is_multicast:
            return False
        if ip.is_reserved:
            return False
        if ip.is_unspecified:       # 0.0.0.0
            return False

        # Specific bogons not always covered
        if ip_str in ("0.0.0.0", "255.255.255.255"):
            return False

        # Carrier-grade NAT (RFC 6598) - not covered by is_private in older Python
        try:
            if ip in ipaddress.ip_network("100.64.0.0/10"):
                return False
        except (ValueError, TypeError):
            pass

        # Documentation/test ranges (RFC 5737)
        for test_range in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
            try:
                if ip in ipaddress.ip_network(test_range):
                    return False
            except (ValueError, TypeError):
                pass

        # Benchmarking (RFC 2544)
        try:
            if ip in ipaddress.ip_network("198.18.0.0/15"):
                return False
        except (ValueError, TypeError):
            pass

        return True

    def _resolve(self, domain):
        try:
            socket.setdefaulttimeout(self.timeout)
            return socket.gethostbyname(domain)
        except (socket.gaierror, socket.timeout, OSError):
            return None

    def _identify_cloud_provider(self, ip):
        for provider, prefixes in CLOUD_PROVIDERS.items():
            for prefix in prefixes:
                if ip.startswith(prefix):
                    return provider
        return None

    # ───────────────────────────────────────────────────────────
    # HTTP probe (active validation)
    # ───────────────────────────────────────────────────────────
    def _http_probe(self, domain, ip):
        """Active HTTP/HTTPS validation. Returns dict with details."""
        cache_key = (domain, ip)
        if cache_key in self._http_cache:
            return self._http_cache[cache_key]

        result = {
            "domain": domain,
            "ip": ip,
            "responds_http": False,
            "responds_https": False,
            "http_status": None,
            "https_status": None,
            "server": None,
            "title": None,
            "headers": {},
            "redirect": None,
            "tls_valid": None,
            "tls_issuer": None,
        }

        # Try HTTPS first (more common in cloud)
        https_resp = self._http_request(domain, ip, port=443, use_ssl=True)
        if https_resp:
            result["responds_https"] = True
            self._fill_response_data(result, https_resp, scheme="https")

        # Then HTTP
        http_resp = self._http_request(domain, ip, port=80, use_ssl=False)
        if http_resp:
            result["responds_http"] = True
            self._fill_response_data(result, http_resp, scheme="http")

        self._http_cache[cache_key] = result
        return result

    def _http_request(self, domain, ip, port, use_ssl):
        """Send a HEAD request to the IP using Host header for vhosting."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            tls_info = {}
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=domain)

            if sock.connect_ex((ip, port)) != 0:
                sock.close()
                return None

            # Capture cert if HTTPS
            if use_ssl:
                try:
                    cert = sock.getpeercert()
                    if cert:
                        tls_info["valid"] = True
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        tls_info["issuer"] = issuer.get("organizationName")
                except (ssl.SSLError, AttributeError):
                    tls_info["valid"] = False

            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {domain}\r\n"
                f"User-Agent: CameraAudit/1.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            sock.send(req)

            data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 32768:
                        break
                except socket.timeout:
                    break
            sock.close()

            if not data:
                return None

            return self._parse_http_response(data, tls_info)
        except (socket.error, ssl.SSLError, OSError):
            return None

    def _parse_http_response(self, data, tls_info=None):
        try:
            decoded = data.decode("utf-8", errors="replace")
            parts = decoded.split("\r\n\r\n", 1)
            header_section = parts[0]
            body = parts[1] if len(parts) > 1 else ""

            lines = header_section.split("\r\n")
            first_line = lines[0] if lines else ""
            status_match = re.search(r"HTTP/[\d.]+\s+(\d+)", first_line)
            status_code = int(status_match.group(1)) if status_match else None

            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            # Title extraction
            title_match = re.search(
                r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE
            )
            title = title_match.group(1).strip()[:120] if title_match else None

            return {
                "status": status_code,
                "headers": headers,
                "body": body,
                "title": title,
                "tls": tls_info or {},
            }
        except Exception:
            return None

    def _fill_response_data(self, result, parsed, scheme):
        if scheme == "https":
            result["https_status"] = parsed["status"]
        else:
            result["http_status"] = parsed["status"]

        # Prefer HTTPS data for fields
        if scheme == "https" or not result.get("server"):
            result["server"] = parsed["headers"].get("server")
            result["title"] = parsed["title"] or result.get("title")
            result["headers"].update(parsed["headers"])

            # Redirect tracking
            location = parsed["headers"].get("location")
            if location:
                result["redirect"] = location

            tls = parsed.get("tls", {})
            if tls.get("valid") is not None:
                result["tls_valid"] = tls["valid"]
                result["tls_issuer"] = tls.get("issuer")

    # ───────────────────────────────────────────────────────────
    # Endpoint classification (the actual work)
    # ───────────────────────────────────────────────────────────
    def _classify_subdomain(self, domain, ip, vendor):
        """Multi-layer classification. Returns (severity, reason, evidence)."""
        # Layer 1: IP must be public
        if not self._is_public_ip(ip):
            return None  # Discard entirely

        # Layer 2: Probe HTTP
        probe = self._http_probe(domain, ip)

        responds = probe["responds_http"] or probe["responds_https"]
        is_dev_pattern = any(
            k in domain.lower() for k in
            ["staging", "stage-", "-stage", "dev", "-dev",
             "test", "-test", "qa", "-qa", "internal"]
        )

        # Layer 3: Alias detection (same IP as production)
        prod_ips = self._prod_ips.get(vendor, set())
        is_alias = ip in prod_ips

        if not responds:
            # DNS exists but no HTTP service
            sev = "info"
            reason = "DNS resolves but no HTTP/HTTPS service"
            return (sev, reason, {
                "ip": ip,
                "is_dev_pattern": is_dev_pattern,
                "is_alias_of_production": is_alias,
                "responds": False,
            })

        # If alias of production, no real "dev exposure" — informational
        if is_alias:
            sev = "info"
            reason = "Subdomain is alias of production (same IP)"
            return (sev, reason, {
                "ip": ip,
                "is_alias_of_production": True,
                "responds": True,
                "https_status": probe["https_status"],
                "server": probe["server"],
            })

        # Layer 4: Status code based classification
        status = probe["https_status"] or probe["http_status"]

        # Detect dev/staging indicators
        env_revealed = None
        for hdr_name in DEV_INDICATOR_HEADERS:
            if hdr_name in probe["headers"]:
                env_revealed = (hdr_name, probe["headers"][hdr_name])
                break

        # Check for stack trace in body (errors)
        body_sample = probe.get("title") or ""
        # We don't have body in result anymore but title can hint
        title_indicates_error = any(
            t in (probe["title"] or "").lower()
            for t in ["error", "exception", "stack trace", "whitelabel"]
        )

        # Layer 5: Sensitive path probing for endpoints that respond 200
        sensitive_finding = None
        if status == 200 and is_dev_pattern:
            sensitive_finding = self._probe_sensitive_paths(domain, ip)

        # Classify
        if status in (401, 403):
            sev = "low"
            reason = f"Endpoint exists but auth-protected (HTTP {status})"
        elif status in (301, 302, 303, 307, 308):
            redirect = probe.get("redirect", "?")
            sev = "info"
            reason = f"Redirects to: {redirect}"
        elif status == 200:
            if sensitive_finding:
                sev = "high"
                reason = f"Exposes sensitive path: {sensitive_finding['path']}"
            elif env_revealed:
                sev = "high"
                reason = (f"Dev/staging confirmed via "
                          f"header {env_revealed[0]}={env_revealed[1]}")
            elif title_indicates_error:
                sev = "medium"
                reason = f"Returns error page: '{probe['title']}'"
            elif is_dev_pattern:
                sev = "medium"
                reason = "Dev/staging-like name returns 200 OK without auth"
            else:
                sev = "info"
                reason = "Endpoint accessible (200 OK)"
        elif status and status >= 500:
            sev = "medium"
            reason = f"Server error (HTTP {status}) - may leak info"
        else:
            sev = "info"
            reason = f"HTTP {status} response"

        evidence = {
            "ip": ip,
            "responds": True,
            "https_status": probe["https_status"],
            "http_status": probe["http_status"],
            "server": probe["server"],
            "title": probe["title"],
            "tls_valid": probe["tls_valid"],
            "tls_issuer": probe["tls_issuer"],
            "is_dev_pattern": is_dev_pattern,
            "is_alias_of_production": is_alias,
            "env_header": env_revealed,
            "redirect": probe.get("redirect"),
            "sensitive_path": sensitive_finding,
        }

        return (sev, reason, evidence)

    def _probe_sensitive_paths(self, domain, ip):
        """Quick check for over-exposed paths on a responsive endpoint."""
        for path, label in SENSITIVE_PATHS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=domain)
                if sock.connect_ex((ip, 443)) != 0:
                    sock.close()
                    continue

                req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {domain}\r\n"
                    f"User-Agent: CameraAudit/1.0\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                sock.send(req)
                resp = sock.recv(2048)
                sock.close()

                if not resp:
                    continue
                first_line = resp.split(b"\r\n", 1)[0].decode(errors="replace")
                if " 200 " in first_line:
                    return {"path": path, "label": label,
                            "status": 200, "url": f"https://{domain}{path}"}
            except (socket.error, ssl.SSLError, OSError):
                continue
        return None

    # ───────────────────────────────────────────────────────────
    # Subdomain bruteforce (with classification)
    # ───────────────────────────────────────────────────────────
    def _subdomain_brute(self, base_domain, resolved_dict, vendor):
        parts = base_domain.split(".")
        if len(parts) < 2:
            return

        if len(parts) >= 3:
            root = ".".join(parts[-2:])
        else:
            root = base_domain

        if self.verbose:
            print(f"    [i] Subdomain bruteforce on {root}")

        found_subs = []

        def try_sub(sub):
            test_domain = f"{sub}.{root}"
            ip = self._resolve(test_domain)
            if ip:
                return test_domain, ip
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(try_sub, s) for s in SUBDOMAIN_WORDLIST]
            for future in as_completed(futures):
                result = future.result()
                if not result:
                    continue
                domain, ip = result
                if domain in resolved_dict:
                    continue

                resolved_dict[domain] = ip

                # Skip private IPs entirely (no finding produced)
                if not self._is_public_ip(ip):
                    if self.verbose >= 2:
                        print(f"    [skip] {domain} -> {ip} (private)")
                    continue

                # Classify
                classification = self._classify_subdomain(domain, ip, vendor)
                if not classification:
                    continue

                severity, reason, evidence = classification
                found_subs.append({
                    "domain": domain,
                    "ip": ip,
                    "severity": severity,
                    "reason": reason,
                })

                # Title based on severity
                if severity == "high":
                    title = f"Exposed Endpoint: {domain}"
                elif severity == "medium":
                    title = f"Suspicious Endpoint: {domain}"
                elif severity == "low":
                    title = f"Protected Endpoint: {domain}"
                else:
                    title = f"Discovered Subdomain: {domain}"

                self.findings.append({
                    "type": "cloud_subdomain_classified",
                    "severity": severity,
                    "title": title,
                    "description": reason,
                    "target": domain,
                    "evidence": evidence
                })

                if severity in ("high", "medium") and self.verbose:
                    print(f"    [{severity.upper()}] {domain}: {reason}")
                elif self.verbose >= 2:
                    print(f"    [{severity}] {domain}: {reason}")

        if found_subs and self.verbose:
            n_real = sum(1 for s in found_subs if s["severity"] in ("high", "medium"))
            print(f"    [+] Found {len(found_subs)} subdomains "
                  f"({n_real} actionable, rest informational)")

    # ───────────────────────────────────────────────────────────
    # TLS cert analysis
    # ───────────────────────────────────────────────────────────
    def _analyze_cert(self, domain, ip):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 443))
            ssock = ctx.wrap_socket(sock, server_hostname=domain)
            cert = ssock.getpeercert()
            ssock.close()

            if not cert:
                return

            sans = []
            for entry in cert.get("subjectAltName", []):
                if entry[0] == "DNS":
                    sans.append(entry[1])

            interesting_sans = []
            domain_root = ".".join(domain.split(".")[-2:])
            for san in sans:
                if domain_root not in san and not san.startswith("*"):
                    interesting_sans.append(san)

            if interesting_sans:
                self.findings.append({
                    "type": "cloud_cert_leak",
                    "severity": "low",
                    "title": f"TLS Cert SAN Discloses Other Hosts: {domain}",
                    "description": "Certificate's SAN field reveals additional infrastructure",
                    "target": domain,
                    "evidence": interesting_sans[:15]
                })

            issuer = dict(x[0] for x in cert.get("issuer", []))
            issuer_o = issuer.get("organizationName", "Unknown")
            if self.verbose >= 2:
                print(f"    [i] {domain}: issuer={issuer_o}, SANs={len(sans)}")

        except (socket.error, ssl.SSLError, OSError, socket.timeout):
            pass

    def detect_vendor_from_target(self, target):
        try:
            hostname = socket.gethostbyaddr(target)[0]
            for vendor in VENDOR_DOMAINS:
                if vendor.lower() in hostname.lower():
                    return vendor
        except (socket.herror, socket.gaierror):
            pass
        return None
