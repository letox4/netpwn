"""Descubrimiento de hosts en la LAN mediante un barrido ARP."""
import ipaddress

from scapy.all import ARP, Ether, conf, srp


def vendor_for(mac: str) -> str:
    try:
        return conf.manufdb._get_manuf(mac) or ""
    except Exception:
        return ""


def _clean_vendor(mac: str, vendor: str) -> str:
    """scapy devuelve el propio MAC cuando la OUI es desconocida."""
    if not vendor or vendor.strip().lower() == (mac or "").lower():
        return ""
    return vendor


def scan(interface: str, cidr: str, timeout: float = 2.0) -> list[dict]:
    """Envia un ARP who-has a todo el rango y devuelve los que responden.

    Importante en Wi-Fi: mandar 256 broadcast de golpe desborda la cola del
    driver y se pierden respuestas. Se pacea con `inter` y se reintenta una
    pasada para los que no contestaron la primera vez.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []

    def _arp_for(ip: str):
        return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    all_ips = [str(h) for h in net.hosts()]
    answered: dict[str, str] = {}  # ip -> mac

    def _sweep(ips: list[str], inter: float, tmo: float) -> None:
        pkts = [_arp_for(ip) for ip in ips]
        ans, _ = srp(pkts, iface=interface, timeout=tmo, inter=inter,
                     verbose=0)
        for _, reply in ans:
            if reply.haslayer(ARP):
                answered[reply[ARP].psrc] = reply[ARP].hwsrc

    # Pasada 1: paceo suave. Pasada 2: solo los que no respondieron.
    _sweep(all_ips, inter=0.002, tmo=timeout)
    missed = [ip for ip in all_ips if ip not in answered]
    if missed:
        _sweep(missed, inter=0.01, tmo=timeout + 1.0)

    hosts = []
    for ip, mac in answered.items():
        hosts.append({"ip": ip, "mac": mac,
                      "vendor": _clean_vendor(mac, vendor_for(mac))})
    hosts.sort(key=lambda h: tuple(int(o) for o in h["ip"].split(".")))
    return hosts
