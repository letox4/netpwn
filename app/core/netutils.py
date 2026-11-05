"""Utilidades de red: listar interfaces y descubrir el gateway por defecto."""
import ipaddress
import os

try:
    import netifaces
except ImportError:  # netifaces2 expone el mismo modulo
    netifaces = None


def to_cidr(ip: str | None, netmask: str | None) -> str | None:
    if not ip or not netmask:
        return None
    try:
        net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(net)
    except Exception:
        return None


def list_interfaces() -> list[dict]:
    if netifaces is None:
        return []
    result = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        inet = addrs.get(netifaces.AF_INET, [{}])
        inet = inet[0] if inet else {}
        link = addrs.get(netifaces.AF_LINK, [{}])
        link = link[0] if link else {}
        ip = inet.get("addr")
        # netifaces original usa "netmask"; netifaces2 usa "mask".
        netmask = inet.get("netmask") or inet.get("mask")
        wireless = os.path.exists(f"/sys/class/net/{iface}/wireless") or os.path.exists(
            f"/sys/class/net/{iface}/phy80211"
        )
        # Loopback fuera. Sin IPv4 solo mostramos Wi-Fi (modo monitor no tiene IP).
        if iface == "lo" or (ip or "").startswith("127."):
            continue
        if not ip and not wireless:
            continue
        result.append(
            {
                "name": iface,
                "ip": ip,
                "netmask": netmask,
                "mac": link.get("addr"),
                "cidr": to_cidr(ip, netmask),
                "wireless": wireless,
            }
        )
    return result


def default_gateway() -> dict | None:
    if netifaces is None:
        return None
    gws = netifaces.gateways()
    # netifaces original: {"default": {AF_INET: (ip, iface, flag), ...}}
    # netifaces2: no crea la clave "default"; el gateway lleva flag True en 3a posicion.
    default = gws.get("default") or {}
    entry = default.get(netifaces.AF_INET)
    if entry:
        return {"ip": entry[0], "iface": entry[1]}
    for entry in gws.get(netifaces.AF_INET) or []:
        # entrada: [ip, iface, es_default] (netifaces2)
        if entry and (len(entry) < 3 or entry[2]):
            return {"ip": entry[0], "iface": entry[1]}
    return None
