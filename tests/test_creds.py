"""Tests del detector de credenciales con paquetes sinteticos.

No hace falta red: se alimenta CredSniffer._process con objetos que imitan
la interfaz de scapy (haslayer / __getitem__).
"""
from scapy.all import IP, Raw, TCP

from modules.creds import CredSniffer


class FakePkt:
    """Minimo objeto con la interfaz de paquete scapy que usa CredSniffer."""

    def __init__(self, load: bytes, src="10.0.0.2", dst="10.0.0.1", sport=12345, dport=80):
        self._load = load
        self._src = src
        self._dst = dst
        self._sport = sport
        self._dport = dport

    def haslayer(self, cls):
        if cls is Raw:
            return True
        if cls is IP:
            return True
        if cls is TCP:
            return True
        return False

    def __getitem__(self, cls):
        if cls is Raw:
            return self
        if cls is IP:
            return self
        return self  # TCP: solo se consultan sport/dport

    @property
    def load(self):
        return self._load

    @property
    def src(self):
        return self._src

    @property
    def dst(self):
        return self._dst

    @property
    def sport(self):
        return self._sport

    @property
    def dport(self):
        return self._dport


def _collect(load: str, **kw) -> list[dict]:
    sniffer = CredSniffer("eth0")
    emitted = []
    sniffer._emit = lambda proto, data, src, dst: emitted.append((proto, data))
    sniffer._process(FakePkt(load.encode(), **kw))
    return emitted


def test_detecta_http_basic():
    import base64
    cred = base64.b64encode(b"admin:SuperSecret1").decode()
    found = _collect(f"GET / HTTP/1.1\r\nAuthorization: Basic {cred}\r\n")
    assert any(p == "HTTP-Basic" and "admin:SuperSecret1" in d for p, d in found)


def test_detecta_formulario_post():
    found = _collect("POST /login HTTP/1.1\r\n\r\nuser=admin&password=hunter2")
    assert any(p == "HTTP-Form" for p, d in found)


def test_detecta_bearer():
    found = _collect("GET /api HTTP/1.1\r\nAuthorization: Bearer eyJhbGciOi.abc.def")
    assert any(p == "Token-Bearer" for p, d in found)


def test_detecta_json_cred():
    found = _collect('POST /api HTTP/1.1\r\n\r\n{"username": "bob", "password": "s3cret0"}')
    assert any(p == "JSON-Cred" for p, d in found)


def test_detecta_ntlmssp():
    found = _collect(b"NTLMSSP\x00\x02\x00\x00\x00".decode(errors="ignore"))
    # _process decodifica con errors=ignore, el magic sigue presente
    assert any(p == "NTLMSSP" for p, d in found)


def test_paquete_sin_credenciales_no_emite():
    found = _collect("GET /style.css HTTP/1.1\r\nHost: example.com")
    assert found == []
