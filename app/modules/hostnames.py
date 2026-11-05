"""Resolucion de nombres de host en LAN: rDNS, mDNS y NetBIOS.

El nombre del dispositivo suele ser la pista mas fiable para clasificarlo
("xiaomi-15t-pro", "sala-familiar", "pc3269"). Se obtiene por tres caminos:
  * rDNS (PTR) via gethostbyaddr: lo que nmap muestra como hostname.
  * mDNS: consulta PTR multicast a 224.0.0.251:5353 por servicios comunes
    (Chromecast, AirPlay, impresoras, ESPHome, HAP...). No intrusivo: es una
    consulta que cualquier cliente de la red hace constantemente.
  * NetBIOS NBSTAT: query UDP/137 unicast, tipica de equipos Windows.
"""
import ipaddress
import socket
import random
import struct
from concurrent.futures import ThreadPoolExecutor

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff


def reverse_dns(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
        if not name or name.replace(".", "").isdigit():
            return None
        return name.split(".")[0]
    except Exception:
        return None


# ------------------------------------------------------------------ mDNS ----
_MDNS_SERVICES = [
    "_googlecast._tcp.local",      # Chromecast / Android TV
    "_airplay._tcp.local",         # Apple TV / iPhones / Sonos
    "_raop._tcp.local",            # AirPlay audio
    "_workstation._tcp.local",     # equipos generales
    "_ipp._tcp.local",             # impresoras
    "_printer._tcp.local",
    "_smb._tcp.local",             # Windows / NAS
    "_hap._tcp.local",             # HomeKit
    "_esphomelib._tcp.local",      # ESPHome IoT
    "_spotify-connect._tcp.local",
    "_dlna._tcp.local",
]

_MDNS_GROUP = "224.0.0.251"


def _clean_name(raw) -> str:
    try:
        name = raw.decode(errors="ignore") if isinstance(raw, bytes) else str(raw)
    except Exception:
        return ""
    name = name.rstrip(".")
    if not name or name.replace(".", "").isdigit():
        return ""
    # Quita el sufijo de servicio: "Sala-TV._googlecast._tcp.local" -> "Sala-TV"
    first = name.split(".")[0]
    return first


def mdns_names(interface: str, timeout: float = 2.5) -> dict[str, str]:
    """Consulta servicios mDNS comunes y devuelve {ip: nombre} de las respuestas.

    Una sola ronda de consultas PTR + escucha breve. Total ~timeout segundos.
    """
    names: dict[str, str] = {}

    def _walk_rrs(rrs) -> None:
        # Recorre la cadena de RRs (scapy encadena los registros en .payload,
        # iterar el objeto solo da los campos del primer registro).
        rr = rrs
        while isinstance(rr, DNSRR):
            try:
                if int(rr.type) == 1:  # A record
                    ip = str(rr.rdata)
                    label = _clean_name(rr.rrname)
                    if ip and label and not _is_mdns_ip_label(label):
                        names.setdefault(ip, label)
            except Exception:
                pass
            rr = rr.payload

    def _on_dns(pkt) -> None:
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        # Respuestas: recorre la cadena de RRs en an y ar (muchos responders
        # ponen los A records en los additional records).
        _walk_rrs(dns.an)
        _walk_rrs(dns.ar)

    try:
        from scapy.all import AsyncSniffer
    except ImportError:
        return names
    questions = [(svc, "PTR", "IN") for svc in _MDNS_SERVICES]
    query = (
        IP(dst=_MDNS_GROUP)
        / UDP(sport=5353, dport=5353)
        / DNS(id=0, rd=0, questions=questions)  # id=0 segun RFC 6762
    )
    sn = AsyncSniffer(iface=interface, filter="udp port 5353", prn=_on_dns, store=False)
    sn.start()
    try:
        send(query, iface=interface, verbose=0, count=2, inter=timeout / 2.5)
    except Exception:
        pass
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.1)
    try:
        sn.stop()
    except Exception:
        pass
    return names


def _is_mdns_ip_label(label: str) -> bool:
    return label.replace(".", "").isdigit()


# ------------------------------------------------------------------ NetBIOS --
def netbios_name(ip: str, timeout: float = 0.8) -> str | None:
    """Query NBSTAT (UDP/137) y devuelve el primer nombre registrado."""
    tid = random.randint(1, 0xFFFF)
    # Nombre comodin '*' codificado first-level encoding (32 bytes: len 0x20,
    # "CK" + 30 'A' en mitad de rango, terminador 0x00), qtype=NBSTAT(0x21)
    encoded = b"\x20" + b"CK" + b"A" * 30 + b"\x00"
    pkt = struct.pack("!HHHHHH", tid, 0, 1, 0, 0, 0) + encoded + struct.pack("!HH", 0x21, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(1024)
    except Exception:
        return None
    finally:
        s.close()
    return _parse_nbstat(data)


def _parse_nbstat(data: bytes) -> str | None:
    try:
        # salta cabecera (12) + RR name: 1 byte len + len bytes + 1 nulo
        off = 12
        name_len = data[off]
        off += 1 + name_len + 1
        # type(2) class(2) ttl(4) rdlen(2)
        rdlen = struct.unpack("!H", data[off + 8:off + 10])[0]
        body = data[off + 10:off + 10 + rdlen]
        if not body:
            return None
        # Formato fijo NBSTAT: body[0]=num_names, luego por cada nombre
        # 15 bytes ASCII + 1 byte sufijo + 2 bytes flags (sin longitud).
        count = body[0]
        idx = 1
        skip = {"WORKGROUP", "__MSBROWSE__"}
        fallback = None
        for _ in range(count):
            if idx + 18 > len(body):
                break
            name = body[idx:idx + 15].decode("ascii", errors="ignore").strip()
            suffix = body[idx + 15]
            # idx += 16 + 2  # nombre(15) + sufijo(1) + flags(2)
            idx += 18
            if not name or name in skip:
                continue
            # Sufijo 0x00 = nombre de estacion de trabajo: el mejor candidato.
            if suffix == 0x00:
                return name
            if fallback is None:
                fallback = name
        return fallback
    except Exception:
        return None


def resolve_hostnames(ips: list[str], mdns_map: dict[str, str] | None = None,
                      netbios: bool = False) -> dict[str, str]:
    """Devuelve {ip: mejor_nombre} combinando rDNS, mDNS y NBSTAT."""
    mdns_map = mdns_map or {}
    # rDNS en paralelo: cada consulta puede tardar segundos si no hay PTR.
    with ThreadPoolExecutor(max_workers=32) as pool:
        rdns_results = list(pool.map(reverse_dns, ips))
    out: dict[str, str] = {}
    for ip, rdns_name in zip(ips, rdns_results):
        name = mdns_map.get(ip) or rdns_name
        if not name and netbios:
            # NetBIOS es unicast intrusivo: fallback secuencial.
            name = netbios_name(ip)
        if name:
            out[ip] = name
    return out
