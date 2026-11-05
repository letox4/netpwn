"""Descubrimiento de topologia de red: construye un grafo de dispositivos.

Dos modos:
  * Sigiloso (footprinting): solo ICMP para TTL, OUI del fabricante y DNS
    inverso. Nada que un IDS de red considere un escaneo.
  * Agresivo (fingerprinting): ademas escanea un set reducido de puertos
    discriminadores de tipo de dispositivo y lee banners.

La salida es un grafo {nodes, edges} listo para pintar en la interfaz.
"""
import asyncio
import ipaddress
import re
import socket
from collections import Counter

from scapy.all import AsyncSniffer, IP as IP_LAYER

from core.bus import bus
from core import netutils
from modules import discovery, fingerprint, hostnames, portscan

# ------------------------------------------------------------------ senales

# Puertos que delatan el tipo de dispositivo (set reducido, no un full scan).
_FINGERPRINT_PORTS = [
    22, 23, 53, 80, 102, 139, 443, 445, 502, 631, 9100, 161, 1900, 2222,
    2404, 3389, 4840, 5000, 5353, 554, 8009, 8080, 8443, 9600, 20000,
    32400, 3689, 44818, 62078, 49152, 17185, 8888,
]

# OUI del fabricante -> tipo de dispositivo (match por subcadena, el primero
# que coincide gana: las claves mas especificas deben ir ANTES).
_VENDOR_TYPES: list[tuple[str, str]] = [
    # Moviles: claves especificas de fabricante antes que las genericas
    # ("xiaomi communications" antes que "xiaomi", etc.)
    ("xiaomi communications", "phone"), ("samsung electronics", "phone"),
    # Planta / OT (antes que las marcas IT, el primero que coincide gana)
    ("rockwell", "plc"), ("allen-bradley", "plc"), ("allen bradley", "plc"),
    ("siemens", "plc"), ("schneider", "plc"), ("modicon", "plc"),
    ("omron", "plc"), ("beckhoff", "plc"), ("wago", "plc"),
    ("phoenix contact", "plc"), ("mitsubishi electric", "plc"),
    ("keyence", "plc"), ("unitronics", "plc"), ("br automation", "plc"),
    ("abb robotics", "robot"), ("fanuc", "robot"), ("kuka", "robot"),
    ("universal robots", "robot"), ("yaskawa", "robot"),
    ("abb", "drive"), ("danfoss", "drive"), ("sew-eurodrive", "drive"),
    ("lenze", "drive"), ("delta electronics", "drive"),
    ("weintek", "hmi"), ("pro-face", "hmi"), ("proface", "hmi"),
    ("maple systems", "hmi"), ("red lion", "hmi"),
    ("schweitzer", "relay"),
    ("moxa", "switch"), ("hirschmann", "switch"), ("westermo", "switch"),
    ("garrettcom", "switch"),
    ("honeywell", "scada"), ("yokogawa", "scada"), ("aveva", "scada"),
    ("wonderware", "scada"), ("inductive automation", "scada"),
    ("tridium", "scada"), ("advantech", "scada"), ("emerson", "scada"),
    ("rosemount", "sensor"), ("endress", "sensor"), ("pepperl", "sensor"),
    ("ifm electronic", "sensor"), ("vega grieshaber", "sensor"),
    ("hms industrial", "gateway"), ("anybus", "gateway"), ("prosoft", "gateway"),
    # Routers / equipos de red
    ("tp-link", "router"), ("mikrotik", "router"), ("cisco", "router"),
    ("zte", "router"), ("d-link", "router"), ("asus", "router"),
    ("netgear", "router"), ("huawei", "router"), ("arcadyan", "router"),
    ("sagemcom", "router"), ("technicolor", "router"), ("compal", "router"),
    ("dell inc.", "pc"), ("dell", "pc"),
    # Impresoras
    ("hewlett", "printer"), ("hp inc.", "printer"), ("canon", "printer"),
    ("epson", "printer"), ("brother", "printer"), ("lexmark", "printer"),
    ("xerox", "printer"), ("ricoh", "printer"), ("kyocera", "printer"),
    # TVs / streaming
    ("lg electronics", "tv"),
    ("vizio", "tv"), ("tcl", "tv"), ("hisense", "tv"), ("sony visual", "tv"),
    ("roku", "tv"), ("amazon technologies", "tv"), ("espressif", "iot"),
    ("tuya", "iot"), ("sonoff", "iot"), ("shenzhen", "iot"),
    ("shelly", "iot"), ("xiaomi", "iot"), ("tasmota", "iot"),
    ("philips lighting", "iot"), ("signify", "iot"),
    # Camaras
    ("hikvision", "camera"), ("dahua", "camera"), ("axis", "camera"),
    ("foscam", "camera"), ("reolink", "camera"), ("wyze", "camera"),
    # ("tp-link","camera") eliminado: ("tp-link","router") va antes y nunca
    # llegaba a matching (entrada muerta).
    # Consolas
    ("sony interactive", "console"), ("microsoft corporation", "pc"),
    ("nintendo", "console"),
    # NAS
    ("synology", "nas"), ("qnap", "nas"), ("western digital", "nas"),
    ("wd", "nas"),
    # Telefonos / tablets
    ("apple", "phone"), ("samsung", "phone"),
    ("oppo", "phone"), ("vivo", "phone"), ("oneplus", "phone"),
    ("google", "phone"), ("motorola", "phone"), ("realme", "phone"),
    ("hon hai", "pc"), ("foxconn", "pc"),
    # PCs / laptops
    ("intel", "pc"), ("asustek", "pc"), ("gigabyte", "pc"), ("msi", "pc"),
    ("lenovo", "pc"), ("acer", "pc"), ("lg electronics", "pc"),
    ("micro-star", "pc"), ("biostar", "pc"), ("american megatrends", "pc"),
    ("raspberry", "iot"), ("arduino", "iot"),
]

# Puertos abiertos -> tipo (muy especificos primero).
_PORT_TYPES: list[tuple[int, str]] = [
    (4840, "scada"),                                # OPC UA
    (9100, "printer"), (631, "printer"),            # JetDirect / IPP
    (3689, "speaker"),                              # AirPlay / DAAP
    (8009, "tv"), (8554, "tv"),                     # Chromecast
    (62078, "phone"),                               # iPhone (lockdownd)
    (554, "camera"),                                # RTSP
    (32400, "nas"),                                 # Plex
    (3389, "pc"), (5985, "pc"),                     # Windows
    (445, "pc"), (139, "pc"), (135, "pc"),
    (22, "pc"), (23, "router"),                     # telnet -> equipo de red
    (161, "router"),                                # SNMP
    (1900, "tv"),                                   # UPnP/SSDP -> SmartTV
    (5000, "iot"), (49152, "iot"), (8888, "iot"),   # firmwares embebidos
]

# Puertos ambiguos: aparecen en PLCs pero tambien en equipos normales
# (2222 = EtherNet/IP, pero tambien SSH alternativo; 44818 idem).
_PORT_TYPES_WEAK: list[tuple[int, str]] = [
    (2222, "plc"), (44818, "plc"),
]

# Pistas en el hostname (rDNS / mDNS / NetBIOS) -> tipo.
_HOSTNAME_TYPES: list[tuple[str, str]] = [
    ("android", "phone"), ("iphone", "phone"), ("ipad", "phone"),
    ("galaxy", "phone"), ("redmi", "phone"), ("pixel", "phone"),
    ("xiaomi", "phone"), ("mi-15", "phone"), ("s25", "phone"),
    ("s24", "phone"), ("s23", "phone"), ("sm-", "phone"),
    ("samsung", "phone"),  # hostname "samsung" = tipico Android Samsung
    ("huawei", "phone"), ("honor", "phone"), ("oppo", "phone"),
    ("vivo", "phone"), ("realme", "phone"), ("oneplus", "phone"),
    ("motorola", "phone"), ("moto-", "phone"), ("nord", "phone"),
    ("desktop-", "pc"), ("laptop", "pc"), ("pc-", "pc"), ("macbook", "pc"),
    ("imac", "pc"), ("thinkpad", "pc"), ("latitude", "pc"), ("esp8266", "iot"),
    ("esp32", "iot"), ("sonos", "speaker"), ("hue-", "iot"), ("tasmota", "iot"),
    ("chromecast", "tv"), ("roku", "tv"), ("firetv", "tv"), ("smart-tv", "tv"),
    ("tv-", "tv"), ("bravia", "tv"), ("shield", "tv"),
    ("printer", "printer"), ("hp-", "printer"), ("canon", "printer"),
    ("camera", "camera"), ("cam-", "camera"), ("nvr", "camera"),
    ("nas", "nas"), ("synology", "nas"),
    ("playstation", "console"), ("ps5", "console"), ("ps4", "console"),
    ("xbox", "console"), ("nintendo", "console"),
    ("compactlogix", "plc"), ("controllogix", "plc"), ("micrologix", "plc"),
    ("s7-1500", "plc"), ("s7-1200", "plc"), ("s7-", "plc"), ("plc", "plc"),
    ("modicon", "plc"), ("wincc-server", "scada"), ("historian", "scada"),
    ("ignition", "scada"), ("wonderware", "scada"), ("scada", "scada"),
    ("panelview", "hmi"), ("wincc", "hmi"), ("weintek", "hmi"), ("hmi", "hmi"),
    ("rtu", "rtu"), ("vfd", "drive"), ("variador", "drive"), ("inversor", "drive"),
    ("rele-", "relay"), ("relay", "relay"), ("sel-", "relay"), ("sel7", "relay"),
    ("fanuc", "robot"), ("kuka", "robot"), ("robot", "robot"),
    ("ies-", "switch"), ("switch", "switch"),
    ("anybus", "gateway"), ("prosoft", "gateway"),
    ("sensor", "sensor"), ("transmisor", "sensor"), ("transmitter", "sensor"),
    ("router", "router"), ("ap-", "router"), ("gateway", "router"),
    # IoT domestico tipico
    ("adc-", "iot"), ("adt-", "iot"), ("roborock", "iot"), ("vacuum", "iot"),
    ("dyson", "iot"), ("shelly", "iot"), ("tasmota", "iot"), ("tuya", "iot"),
    ("nest-", "iot"), ("wemo", "iot"), ("bulb", "iot"), ("strip", "iot"),
]

# Etiquetas amigables e iconos por tipo (el icono lo resuelve el frontend).
TYPE_LABELS = {
    "router": "Router / Equipo de red",
    "pc": "PC / Laptop",
    "phone": "Movil / Tablet",
    "tv": "TV / Streaming",
    "printer": "Impresora",
    "iot": "Dispositivo IoT",
    "camera": "Camara",
    "console": "Consola",
    "nas": "NAS / Almacenamiento",
    "speaker": "Audio / Smart speaker",
    "plc": "PLC",
    "hmi": "HMI / Panel",
    "rtu": "RTU",
    "scada": "SCADA / Ingenieria",
    "drive": "Variador",
    "relay": "Rele de proteccion",
    "robot": "Robot",
    "switch": "Switch industrial",
    "gateway": "Pasarela OT",
    "sensor": "Instrumento de campo",
    "self": "Tu maquina",
    "unknown": "Desconocido",
}


def _vendor_type(vendor: str) -> str | None:
    vl = (vendor or "").lower()
    for key, dev_type in _VENDOR_TYPES:
        if key in vl:
            return dev_type
    return None


def _port_type(open_ports: list[int]) -> str | None:
    for port, dev_type in _PORT_TYPES:
        if port in open_ports:
            return dev_type
    return None


def _port_type_weak(open_ports: list[int]) -> str | None:
    for port, dev_type in _PORT_TYPES_WEAK:
        if port in open_ports:
            return dev_type
    return None


def _hostname_type(hostname: str) -> str | None:
    # Tokeniza el hostname ("sm-r870.sala" -> ["sm", "r870", "sala"]) y
    # comprueba si algun token EMPIEZA por la clave: evita que "crowd-sensor"
    # dispare "sensor" por subcadena cruda y a la vez "s25u" matchee "s25".
    tokens = [t for t in re.split(r"[-_.]", (hostname or "").lower()) if t]
    if not tokens:
        return None
    for key, dev_type in _HOSTNAME_TYPES:
        # claves con guion final ("sm-") no pueden matchear tras el split:
        # se comparan sin el guion.
        k = key.rstrip("-")
        if not k:
            continue
        if any(t.startswith(k) for t in tokens):
            return dev_type
    return None


def _ttl_type(ttl: int | None) -> str | None:
    if ttl is None:
        return None
    if ttl > 200:
        return "router"  # equipo de red puro
    if ttl > 100:
        return "pc"      # pila Windows
    return None          # 64: Linux vale para casi todo, no discrimina


def classify(vendor: str, hostname: str, ttl: int | None,
             open_ports: list[int], is_gateway: bool) -> dict:
    """Combina todas las pistas y decide el tipo con un mini sistema de votos.

    Solo los votos FUERTES (vendor, hostname, puertos discriminadores, gateway)
    pueden definir el tipo. Los debiles (22/23/161/2222/44818, TTL) solo
    desempatan: si no hay nada fuerte, es "unknown" en vez de inventarse un tipo.
    """
    strong_votes: dict[str, int] = {}
    weak_votes: dict[str, int] = {}

    def svote(dev_type: str | None, weight: int) -> None:
        if dev_type:
            strong_votes[dev_type] = strong_votes.get(dev_type, 0) + weight

    def wvote(dev_type: str | None, weight: int) -> None:
        if dev_type:
            weak_votes[dev_type] = weak_votes.get(dev_type, 0) + weight

    weak_ports = [p for p in open_ports if p in (22, 23, 161, 2222, 44818)]
    strong_ports = [p for p in open_ports if p not in (22, 23, 161, 2222, 44818)]

    svote(_port_type(strong_ports), 4)          # puertos discriminadores
    wvote(_port_type(weak_ports) or _port_type_weak(weak_ports), 1)
    svote(_vendor_type(vendor), 3)              # OUI del fabricante
    svote(_hostname_type(hostname), 3)          # nombre de host
    wvote(_ttl_type(ttl), 1)                    # TTL solo desempata red/windows

    votes = strong_votes
    if is_gateway:
        votes["router"] = votes.get("router", 0) + 10

    if not votes:
        # Sin pistas fuertes: no clasificamos aunque haya votos debiles.
        dev_type, confidence = "unknown", 0
    else:
        dev_type = max(votes, key=votes.get)
        confidence = min(100, votes[dev_type] * 12)

    # Pistas humanas para mostrar en el nodo
    evidence = []
    if open_ports:
        pt = _port_type(open_ports)
        if pt:
            evidence.append(f"puertos {open_ports[:6]}")
    if vendor:
        evidence.append(f"OUI: {vendor}")
    if hostname:
        evidence.append(f"hostname: {hostname}")
    if ttl:
        evidence.append(f"TTL={ttl}")

    return {"type": dev_type, "confidence": confidence, "evidence": evidence}


def _reverse_dns(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
        if not name or name.replace(".", "").isdigit():
            return None  # rDNS que solo devuelve la IP
        return name.split(".")[0]
    except Exception:
        return None


def _clean_vendor(mac: str, vendor: str) -> str:
    """scapy devuelve el propio MAC cuando la OUI es desconocida."""
    if not vendor or vendor.strip().lower() == (mac or "").lower():
        return ""
    return vendor


async def _fingerprint_host(ip: str, mac: str, vendor: str, is_gateway: bool,
                            aggressive: bool, timeout: float,
                            mdns_map: dict[str, str] | None = None) -> dict:
    # Nombre: mDNS (recogido en una ronda previa) -> rDNS -> NetBIOS (agresivo)
    hostname = (mdns_map or {}).get(ip)
    if not hostname:
        hostname = await asyncio.to_thread(hostnames.reverse_dns, ip)
    if not hostname and aggressive:
        hostname = await asyncio.to_thread(hostnames.netbios_name, ip)
    open_ports: list[int] = []

    if aggressive:
        # Set reducido y rapido: solo para clasificar, no es un escaneo completo.
        try:
            result = await portscan.scan(ip, _FINGERPRINT_PORTS, timeout=0.5,
                                         concurrency=32, grab_banner=False,
                                         mode="connect")
            # portscan solo devuelve los puertos que respondieron (abiertos).
            open_ports = [p["port"] for p in result]
        except Exception:
            open_ports = []

    # TTL con ICMP (rapido y silencioso).
    fp = await fingerprint.guess_async(ip, mac, open_ports, timeout=timeout)
    ttl = fp.get("ttl")

    info = classify(_clean_vendor(mac, vendor), hostname, ttl, open_ports, is_gateway)
    os_guess = fp.get("os") or ""
    return {
        "ip": ip, "mac": mac, "vendor": _clean_vendor(mac, vendor),
        "hostname": hostname,
        "ttl": ttl, "os": os_guess, "open_ports": open_ports,
        "type": info["type"], "confidence": info["confidence"],
        "evidence": info["evidence"],
    }


async def analyze_traffic(interface: str, cidr: str, seconds: float = 15.0) -> dict:
    """Escucha el trafico IP durante `seconds` y cuenta flujos entre hosts.

    Sin MITM solo se ve trafico broadcast/multicast (mDNS, SSDP, ARP...);
    con el MITM ARP activo pasa todo por aqui y las relaciones son completas.
    Devuelve {pares LAN<->LAN con contador, total de paquetes}.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return {"flows": [], "packets": 0}

    flows: Counter = Counter()
    total = Counter()

    def _on_packet(pkt) -> None:
        if IP_LAYER not in pkt:
            return
        src, dst = pkt[IP_LAYER].src, pkt[IP_LAYER].dst
        total["n"] += 1
        try:
            if ipaddress.ip_address(src) in net and ipaddress.ip_address(dst) in net \
                    and src != dst:
                flows[(src, dst)] += 1
        except ValueError:
            pass

    sniffer = AsyncSniffer(iface=interface, filter="ip", prn=_on_packet, store=False)
    sniffer.start()
    bus.emit({"type": "topology",
              "msg": f"Analizando trafico {seconds:.0f}s (con MITM activo se ve todo)..."})
    await asyncio.sleep(seconds)
    await asyncio.to_thread(sniffer.stop)

    return {
        "flows": [{"source": s, "target": d, "count": c}
                  for (s, d), c in flows.most_common()],
        "packets": total["n"],
    }


async def build(interface: str, cidr: str, aggressive: bool = False,
                traffic_seconds: float = 0) -> dict:
    """Escanea la red y devuelve el grafo {nodes, edges}."""
    bus.emit({"type": "topology", "msg": f"Barrido ARP de {cidr}..."})
    hosts = await asyncio.to_thread(discovery.scan, interface, cidr, 2.0)
    bus.emit({"type": "topology", "msg": f"{len(hosts)} hosts respondieron"})

    # Una ronda de consultas mDNS para toda la red: nombres de Chromecasts,
    # AirPlay, impresoras, IoT... (consulta inofensiva, la hace cualquiera).
    bus.emit({"type": "topology", "msg": "Consultando mDNS (nombres de dispositivos)..."})
    try:
        mdns_map = await asyncio.to_thread(hostnames.mdns_names, interface, 2.5)
    except Exception:
        mdns_map = {}
    if mdns_map:
        bus.emit({"type": "topology",
                  "msg": f"mDNS: {len(mdns_map)} nombres resueltos"})

    gw = netutils.default_gateway()
    gateway_ip = gw["ip"] if gw else None

    # Nuestro propio IP en esa interfaz.
    my_ip = None
    for iface in netutils.list_interfaces():
        if iface["name"] == interface and iface.get("ip"):
            my_ip = iface["ip"]
            break

    nodes: list[dict] = []
    edges: list[dict] = []

    nodes.append({
        "id": "self", "ip": my_ip, "type": "self",
        "label": "Tu maquina", "hostname": None, "mac": None,
        "vendor": None, "os": None, "open_ports": [], "confidence": 100,
        "evidence": [f"interfaz {interface}"],
    })

    if gateway_ip:
        # El gateway tambien suele responder al ARP: si esta en la lista, lo
        # marcamos; si no, lo aniadimos.
        gw_entry = next((h for h in hosts if h["ip"] == gateway_ip), None)
        if gw_entry is None:
            hosts.insert(0, {"ip": gateway_ip, "mac": "", "vendor": ""})
            gw_mac, gw_vendor = "", ""
        else:
            # Reutiliza MAC/OUI reales del gateway si respondio al barrido.
            gw_mac = gw_entry.get("mac") or ""
            gw_vendor = _clean_vendor(gw_mac, gw_entry.get("vendor") or "")
        nodes.append({
            "id": f"gw-{gateway_ip}", "ip": gateway_ip, "type": "router",
            "label": "Gateway", "hostname": None, "mac": gw_mac,
            "vendor": gw_vendor, "os": None, "open_ports": [],
            "confidence": 100,
            "evidence": ["gateway por defecto"],
        })
        edges.append({"source": "self", "target": f"gw-{gateway_ip}"})
        edges.append({"source": f"gw-{gateway_ip}", "target": "internet"})

    nodes.append({
        "id": "internet", "ip": None, "type": "internet",
        "label": "Internet / WAN", "hostname": None, "mac": None,
        "vendor": None, "os": None, "open_ports": [], "confidence": 100,
        "evidence": [],
    })

    tasks = []
    # Limite global de concurrencia: sin el, gather lanza todos los hosts
    # a la vez (sockets y sniffers saturados).
    sem = asyncio.Semaphore(24)

    async def _fingerprint_limited(ip: str, mac: str, vendor: str) -> dict:
        async with sem:
            return await _fingerprint_host(ip, mac, vendor,
                                           is_gateway=False,
                                           aggressive=aggressive, timeout=0.8,
                                           mdns_map=mdns_map)

    for h in hosts:
        if h["ip"] == my_ip or (gateway_ip and h["ip"] == gateway_ip):
            continue
        tasks.append(_fingerprint_limited(h["ip"], h["mac"], h["vendor"]))

    if tasks:
        bus.emit({"type": "topology",
                  "msg": ("Fingerprinting agresivo" if aggressive
                          else "Footprinting sigiloso") + f" de {len(tasks)} hosts..."})
        results = await asyncio.gather(*tasks)
    else:
        results = []

    for r in results:
        node = dict(r)
        node["id"] = f"host-{r['ip']}"
        node["label"] = r["hostname"] or r["ip"]
        nodes.append(node)
        if gateway_ip:
            edges.append({"source": f"gw-{gateway_ip}",
                          "target": f"host-{r['ip']}"})
        else:
            edges.append({"source": "self", "target": f"host-{r['ip']}"})

    # Relaciones inferidas del trafico: aristas host<->host con volumen.
    if traffic_seconds > 0:
        traffic = await analyze_traffic(interface, cidr, traffic_seconds)
        known = {n["ip"]: n["id"] for n in nodes if n.get("ip")}
        edge_keys = {(e.get("source"), e.get("target")) for e in edges}
        for flow in traffic["flows"]:
            a, b = known.get(flow["source"]), known.get(flow["target"])
            if not a or not b or a == b:
                continue
            # Evita duplicar aristas (mismo par source->target ya presente).
            if (a, b) in edge_keys:
                continue
            edge_keys.add((a, b))
            edges.append({"source": a, "target": b,
                          "kind": "traffic", "count": flow["count"]})
        bus.emit({"type": "topology",
                  "msg": f"Trafico: {traffic['packets']} paquetes, "
                         f"{len(traffic['flows'])} flujos entre hosts"})

    # Resumen por tipo para el log
    summary: dict[str, int] = {}
    for n in nodes:
        summary[n["type"]] = summary.get(n["type"], 0) + 1
    bus.emit({"type": "topology",
              "msg": "Topologia lista: " + ", ".join(f"{v} {TYPE_LABELS.get(k, k)}"
                                                     for k, v in summary.items())})

    return {"nodes": nodes, "edges": edges, "aggressive": aggressive}
