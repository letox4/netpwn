"""Modo demo: red ficticia completa para probar NetPwn sin root ni hardware.

Con NETPWN_DEMO=1 la aplicacion arranca en cualquier sistema operativo,
sin sockets raw ni iptables: los endpoints de reconocimiento devuelven una
red de laboratorio inventada (una planta industrial pequena) y un guion de
eventos alimenta la interfaz por WebSocket como si la red estuviera viva.

Ningun dato es real. Rangos 10.10.20.0/24 y documentacion/TEST-CHECKLIST.md.
"""
import asyncio
import os
import random

from core.bus import bus

DEMO_ENV = "NETPWN_DEMO"

# Red ficticia: planta industrial con PLCs, HMIs, SCADA y equipos de oficina.
IFACE = {
    "name": "eth0",
    "ip": "10.10.20.50",
    "netmask": "255.255.255.0",
    "mac": "02:42:ac:11:00:32",
    "cidr": "10.10.20.0/24",
    "wireless": False,
}

GATEWAY = {"ip": "10.10.20.1", "iface": "eth0"}

# ip -> descripcion del host (misma red que el TOPO_DEMO del frontend).
HOSTS = [
    {"ip": "10.10.20.1", "mac": "00:1a:2b:10:00:01", "vendor": "Cisco",
     "os": "Router (TTL 255)", "ttl": 255, "ports": [
         {"port": 22, "service": "ssh", "banner": "SSH-2.0-Cisco-1.25"},
         {"port": 443, "service": "https", "banner": ""}]},
    {"ip": "10.10.20.2", "mac": "00:90:e8:11:22:33", "vendor": "Moxa",
     "os": "Switch (TTL 255)", "ttl": 255, "ports": [
         {"port": 22, "service": "ssh", "banner": "SSH-2.0-MOS-7.4"},
         {"port": 80, "service": "http", "banner": "EMBEDDED HTTPD"},
         {"port": 161, "service": "snmp", "banner": ""}]},
    {"ip": "10.10.20.10", "mac": "00:1b:1b:aa:10:10", "vendor": "Siemens",
     "os": "Linux (TTL 64)", "ttl": 64, "ports": [
         {"port": 102, "service": "iso-tsap", "banner": "Siemens S7-1500"},
         {"port": 443, "service": "https", "banner": ""}]},
    {"ip": "10.10.20.12", "mac": "00:0e:8c:12:12:12", "vendor": "Siemens",
     "os": "Linux (TTL 64)", "ttl": 64, "ports": [
         {"port": 80, "service": "http", "banner": "SIMATIC HMI"},
         {"port": 443, "service": "https", "banner": ""}]},
    {"ip": "10.10.20.20", "mac": "00:0c:29:20:20:20", "vendor": "VMware",
     "os": "Windows (TTL 128)", "ttl": 128, "ports": [
         {"port": 443, "service": "https", "banner": ""},
         {"port": 3389, "service": "ms-wbt-server", "banner": ""},
         {"port": 4840, "service": "opcua", "banner": "OPC-UA Binary"}]},
    {"ip": "10.10.20.25", "mac": "3c:07:54:25:25:25", "vendor": "Dell",
     "os": "Windows (TTL 128)", "ttl": 128, "ports": [
         {"port": 445, "service": "microsoft-ds", "banner": "Windows 10 Pro"},
         {"port": 3389, "service": "ms-wbt-server", "banner": ""}]},
    {"ip": "10.10.20.30", "mac": "00:1b:1b:30:30:30", "vendor": "Danfoss",
     "os": "Linux (TTL 64)", "ttl": 64, "ports": [
         {"port": 80, "service": "http", "banner": "Danfoss VFD"}]},
    {"ip": "10.10.20.40", "mac": "00:a0:f8:40:40:40", "vendor": "GE",
     "os": "Linux (TTL 64)", "ttl": 64, "ports": [
         {"port": 2404, "service": "iec-104", "banner": "IEC 60870-5-104"}]},
]

TOPOLOGY = {
    "nodes": [
        {"id": "self", "ip": IFACE["ip"], "type": "self", "label": "Tu maquina",
         "confidence": 100, "evidence": ["interfaz eth0"]},
        {"id": "gw-10.10.20.1", "ip": "10.10.20.1", "type": "router",
         "label": "FW-PLANTA", "mac": "00:1a:2b:10:00:01", "vendor": "Cisco",
         "confidence": 96, "hostname": "fw-planta", "os": "Router (TTL 255)",
         "ttl": 255, "open_ports": [22, 443],
         "evidence": ["OUI: Cisco", "gateway por defecto"]},
        {"id": "internet", "type": "internet", "label": "Internet / WAN",
         "confidence": 100},
        {"id": "host-10.10.20.2", "ip": "10.10.20.2", "type": "switch",
         "label": "CELDA-SW", "mac": "00:90:e8:11:22:33", "vendor": "Moxa",
         "hostname": "celda-sw", "os": "Switch (TTL 255)", "ttl": 255,
         "open_ports": [22, 80, 161], "confidence": 90,
         "evidence": ["OUI: Moxa", "hostname: switch"]},
        {"id": "host-10.10.20.10", "ip": "10.10.20.10", "type": "plc",
         "label": "S7-1500-LINEA1", "mac": "00:1b:1b:aa:10:10",
         "vendor": "Siemens", "hostname": "s7-1500-linea1", "os": "PLC (TTL 64)",
         "ttl": 64, "open_ports": [102, 443], "confidence": 96,
         "evidence": ["puertos [102]", "OUI: Siemens", "hostname: s7-1500"]},
        {"id": "host-10.10.20.12", "ip": "10.10.20.12", "type": "hmi",
         "label": "HMI-PRENSA", "mac": "00:0e:8c:12:12:12", "vendor": "Siemens",
         "hostname": "hmi-prensa", "os": "Linux (TTL 64)", "ttl": 64,
         "open_ports": [80, 443], "confidence": 84,
         "evidence": ["hostname: hmi"]},
        {"id": "host-10.10.20.20", "ip": "10.10.20.20", "type": "scada",
         "label": "SCADA-SALA", "mac": "00:0c:29:20:20:20", "vendor": "VMware",
         "hostname": "scada-sala", "os": "Windows (TTL 128)", "ttl": 128,
         "open_ports": [443, 4840], "confidence": 92,
         "evidence": ["puertos [4840]", "hostname: scada"]},
        {"id": "host-10.10.20.30", "ip": "10.10.20.30", "type": "drive",
         "label": "VFD-BOMBA", "mac": "00:1b:1b:30:30:30", "vendor": "Danfoss",
         "hostname": "vfd-bomba2", "os": "Variador", "ttl": 64,
         "open_ports": [80], "confidence": 80,
         "evidence": ["OUI: Danfoss", "hostname: vfd"]},
        {"id": "host-10.10.20.40", "ip": "10.10.20.40", "type": "rtu",
         "label": "RTU-SUBEST", "mac": "00:a0:f8:40:40:40", "vendor": "GE",
         "hostname": "rtu-subest", "os": "RTU", "ttl": 64,
         "open_ports": [2404, 20000], "confidence": 94,
         "evidence": ["puertos [2404]", "hostname: rtu"]},
        {"id": "host-10.10.20.25", "ip": "10.10.20.25", "type": "pc",
         "label": "ENG-01", "mac": "3c:07:54:25:25:25", "vendor": "Dell",
         "hostname": "eng-01", "os": "Windows (TTL 128)", "ttl": 128,
         "open_ports": [445, 3389], "confidence": 70,
         "evidence": ["puertos [445, 3389]", "OUI: Dell"]},
    ],
    "edges": [
        {"source": "self", "target": "gw-10.10.20.1"},
        {"source": "gw-10.10.20.1", "target": "internet"},
        {"source": "gw-10.10.20.1", "target": "host-10.10.20.2"},
        {"source": "host-10.10.20.2", "target": "host-10.10.20.10"},
        {"source": "host-10.10.20.2", "target": "host-10.10.20.12"},
        {"source": "host-10.10.20.2", "target": "host-10.10.20.20"},
        {"source": "host-10.10.20.2", "target": "host-10.10.20.30"},
        {"source": "host-10.10.20.2", "target": "host-10.10.20.40"},
        {"source": "host-10.10.20.2", "target": "host-10.10.20.25"},
    ],
}

WIFI_APS = [
    {"ssid": "PLANTA-OT", "bssid": "00:1a:2b:10:00:01", "channel": 6,
     "signal": -48, "enc": "WPA2-PSK"},
    {"ssid": "OFICINA-GUEST", "bssid": "3c:07:54:25:25:25", "channel": 11,
     "signal": -62, "enc": "WPA2"},
    {"ssid": "HiddenNetwork", "bssid": "00:0e:8c:12:12:12", "channel": 1,
     "signal": -71, "enc": "WPA3-SAE"},
]


def is_demo() -> bool:
    return os.environ.get(DEMO_ENV, "") == "1"


def interfaces() -> dict:
    return {"interfaces": [dict(IFACE)], "gateway": dict(GATEWAY)}


def hosts() -> list[dict]:
    return [{"ip": h["ip"], "mac": h["mac"], "vendor": h["vendor"]}
            for h in HOSTS]


def ports_for(ip: str) -> list[dict]:
    for h in HOSTS:
        if h["ip"] == ip:
            return list(h["ports"])
    return []


def envcheck() -> list[dict]:
    return [
        {"level": "ok",
         "msg": "Modo demo: red ficticia, sin permisos de root ni acceso real"},
        {"level": "warn",
         "msg": "Los modulos ofensivos estan desactivados en demo"},
    ]


# --------------------------------------------------------------------------- #
# Guion de eventos: alimenta el WebSocket como si la red estuviera viva
# --------------------------------------------------------------------------- #
async def _emit_packets(n: int) -> None:
    pairs = [("10.10.20.25", "10.10.20.20"), ("10.10.20.10", "10.10.20.1"),
             ("10.10.20.12", "10.10.20.20"), ("10.10.20.1", "10.10.20.40")]
    for src, dst in (pairs[i % len(pairs)] for i in range(n)):
        bus.emit({
            "type": "packet", "proto": "TCP", "src": src, "dst": dst,
            "sport": random.randint(49152, 61000), "dport": 443,
            "len": random.randint(60, 1400), "info": "",
        })
        await asyncio.sleep(0.15)


async def timeline() -> None:
    """Bucle infinito con eventos variados. Solo se lanza en modo demo."""
    bus.emit({"type": "sniff",
              "msg": "Modo demo: eventos ficticios de una red de laboratorio"})
    step = 0
    while True:
        await _emit_packets(4)
        bus.emit({"type": "packet", "proto": "DNS", "src": "10.10.20.25",
                  "dst": "10.10.20.1", "sport": 5353, "dport": 53,
                  "len": 74, "info": random.choice(
                      ["scada-sala.local", "update.siemens.com",
                       "ntp.ubuntu.com", "hmi-prensa.local"])})
        if step % 3 == 0:
            bus.emit({"type": "poison", "proto": "LLMNR", "name": "SCADA-SALA",
                      "src": "10.10.20.25"})
        if step % 4 == 0:
            ap = WIFI_APS[step % len(WIFI_APS)]
            bus.emit({"type": "wifi_ap", **ap})
        if step % 5 == 0:
            bus.emit({"type": "httpreq", "host": "intranet.planta.local",
                      "path": "/login", "dst": "10.10.20.20"})
        if step % 6 == 0:
            bus.emit({"type": "dns6", "qtype": "AAAA",
                      "name": "wpad.planta.local", "src": "10.10.20.25"})
        if step % 7 == 0:
            bus.emit({"type": "camera",
                      "msg": "demo: camara IP ficticia detectada en 10.10.20.60"})
        step += 1
        await asyncio.sleep(1.6)
