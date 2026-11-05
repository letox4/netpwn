"""Fingerprint ligero de sistema operativo / tipo de dispositivo.

Combina tres pistas baratas y rapidas:
  * TTL inicial del paquete de respuesta ICMP (Linux ~64, Windows ~128, red ~255).
  * Fabricante segun la OUI de la MAC (si viene del descubrimiento ARP).
  * Puertos abiertos conocidos (445 -> Windows, 22 -> *nix, etc.).

No pretende competir con nmap -O; busca dar una etiqueta util al instante.
"""
import asyncio

from scapy.all import ICMP, IP, sr1

from core.bus import bus

# Pistas por fabricante (coincidencia por subcadena, en minusculas).
_VENDOR_HINTS = {
    "apple": "Apple (macOS/iOS)",
    "samsung": "Android/Samsung",
    "huawei": "Android/Huawei",
    "xiaomi": "Android/Xiaomi",
    "cisco": "Equipo de red Cisco",
    "tp-link": "Router/AP TP-Link",
    "mikrotik": "Router MikroTik",
    "raspberry": "Raspberry Pi (Linux)",
    "intel": "PC (Intel NIC)",
    "vmware": "VM VMware",
    "microsoft": "Windows / Hyper-V",
}

# Pistas por puerto abierto.
_PORT_HINTS = {
    3389: "Windows (RDP)",
    445: "Windows (SMB)",
    139: "Windows (NetBIOS)",
    135: "Windows (RPC)",
    22: "Linux/Unix (SSH)",
    5985: "Windows (WinRM)",
    548: "macOS (AFP)",
    62078: "iOS",
    9100: "Impresora",
    1883: "Dispositivo IoT (MQTT)",
}


def _os_from_ttl(ttl: int) -> str:
    if ttl <= 0:
        return ""
    if ttl <= 64:
        return "Linux/Unix/Android"
    if ttl <= 128:
        return "Windows"
    return "Equipo de red/router"


def _ttl_probe(ip: str, timeout: float) -> int | None:
    try:
        ans = sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=0)
        if ans is not None and ans.haslayer(IP):
            return int(ans[IP].ttl)
    except Exception:
        return None
    return None


def guess(ip: str, mac: str | None = None, open_ports=None, timeout: float = 1.0) -> dict:
    """Devuelve una mejor conjetura del SO con las pistas disponibles."""
    open_ports = open_ports or []
    hints: list[str] = []

    ttl = _ttl_probe(ip, timeout)
    ttl_guess = _os_from_ttl(ttl) if ttl else ""
    if ttl_guess:
        hints.append(f"TTL={ttl} -> {ttl_guess}")

    if mac:
        vl = mac.lower()
        for key, label in _VENDOR_HINTS.items():
            if key in vl:
                hints.append(label)
                break

    for port in open_ports:
        if port in _PORT_HINTS:
            hints.append(_PORT_HINTS[port])

    # La etiqueta principal: preferimos puertos (muy especificos), luego TTL.
    primary = next((h for p, h in _PORT_HINTS.items() if p in open_ports), ttl_guess or "Desconocido")
    result = {
        "ip": ip,
        "os": primary,
        "ttl": ttl,
        "hints": hints,
    }
    bus.emit({"type": "fingerprint", **result})
    return result


async def guess_async(ip: str, mac=None, open_ports=None, timeout: float = 1.0) -> dict:
    """Envoltorio asincrono: el sondeo scapy corre en un hilo aparte."""
    return await asyncio.to_thread(guess, ip, mac, open_ports, timeout)
