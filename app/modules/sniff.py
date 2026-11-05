"""Sniffer de paquetes en vivo. Emite un resumen de cada paquete IP."""
from scapy.all import DNS, DNSQR, IP, TCP, UDP, AsyncSniffer

from core.bus import bus


class Sniffer:
    def __init__(self, iface: str, bpf: str | None = None):
        self.iface = iface
        self.bpf = bpf or None
        self._sniffer: AsyncSniffer | None = None
        # Rate-limit del bus: como mucho ~20 eventos de paquete por segundo.
        self._emit_count = 0
        self._emit_window = 0.0

    def _process(self, pkt) -> None:
        import time

        if IP not in pkt:
            return
        now = time.monotonic()
        window = int(now)
        if window != self._emit_window:
            self._emit_window = window
            self._emit_count = 0
        self._emit_count += 1
        if self._emit_count > 20:
            return  # por encima de ~20 pkt/s, descartamos el evento
        ip = pkt[IP]
        proto = "IP"
        sport = dport = None
        info = ""
        if TCP in pkt:
            proto = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            proto = "DNS"
            try:
                info = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                info = ""
        bus.emit({
            "type": "packet",
            "proto": proto,
            "src": ip.src,
            "dst": ip.dst,
            "sport": sport,
            "dport": dport,
            "len": len(pkt),
            "info": info,
        })

    def start(self) -> None:
        self._sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf,
                                     prn=self._process, store=False)
        self._sniffer.start()
        bus.emit({"type": "sniff", "msg": f"Sniffer activo en {self.iface}"})

    def stop(self) -> None:
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        bus.emit({"type": "sniff", "msg": "Sniffer detenido"})
