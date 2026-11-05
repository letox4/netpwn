"""Escaneo de puertos TCP: connect() asincrono o SYN stealth (half-open).

El SYN scan completa solo medio handshake (no deja conexiones en los logs de
aplicacion) y va en lotes con retardo configurable. El modo "low noise"
baja la velocidad y anade jitter aleatorio para no cantar ante un IDS.
Soporta rangos, deteccion de servicio por banner y emision de progreso en
vivo por el bus de eventos.
"""
import asyncio
import random
import socket
import time

from core.bus import bus

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443,
    445, 587, 631, 993, 995, 1433, 1521, 1723, 2049, 3306, 3389, 5432,
    5900, 5985, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
]

# Sondas que provocan que ciertos servicios respondan con algo util.
_PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\n\r\n",
}


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except Exception:
        return ""


def parse_ports(spec) -> list[int]:
    """Acepta None, lista de ints, o una cadena tipo '22,80,1000-2000,443'."""
    if spec is None:
        return list(COMMON_PORTS)
    if isinstance(spec, list):
        return [int(p) for p in spec]
    ports: set[int] = set()
    for chunk in str(spec).replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            lo, hi = int(lo), int(hi)
            ports.update(range(min(lo, hi), max(lo, hi) + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p <= 65535)


async def _grab_banner(reader, writer, port: int, timeout: float) -> str:
    """Intenta leer un banner; si el servicio calla, le manda una sonda."""
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=min(timeout, 1.0))
        if not data and port in _PROBES:
            writer.write(_PROBES[port])
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=min(timeout, 1.0))
        text = data.decode(errors="ignore").strip()
        # Primera linea no vacia, acotada para no inundar la UI.
        line = next((ln for ln in text.splitlines() if ln.strip()), "")
        return line[:120]
    except Exception:
        return ""


async def _check(ip, port, timeout, sem, grab, counter) -> dict | None:
    async with sem:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout)
            banner = await _grab_banner(reader, writer, port, timeout) if grab else ""
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            result = {"port": port, "service": service_name(port), "banner": banner}
            bus.emit({"type": "port", "ip": ip, **result})
            return result
        except Exception:
            return None
        finally:
            counter["done"] += 1


async def scan(
    ip: str,
    ports=None,
    timeout: float = 0.6,
    concurrency: int = 800,
    grab_banner: bool = True,
    mode: str = "connect",
    low_noise: bool = False,
) -> list[dict]:
    port_list = parse_ports(ports)
    if mode == "syn":
        return await _syn_scan(ip, port_list, timeout, grab_banner, low_noise)
    if low_noise:
        concurrency = min(concurrency, 32)
    sem = asyncio.Semaphore(concurrency)
    counter = {"done": 0}
    bus.emit({"type": "portscan",
              "msg": f"Escaneando {len(port_list)} puertos en {ip} (connect"
                     f"{'/low-noise' if low_noise else ''})..."})
    results = await asyncio.gather(
        *(_check(ip, p, timeout, sem, grab_banner, counter) for p in port_list)
    )
    open_ports = sorted((r for r in results if r), key=lambda x: x["port"])
    bus.emit({"type": "portscan",
              "msg": f"{ip}: {len(open_ports)} puertos abiertos de {len(port_list)}"})
    return open_ports


# --------------------------------------------------------------------------- #
# SYN scan (stealth, half-open). Requiere root (sockets raw).
# --------------------------------------------------------------------------- #
def _syn_sync(ip: str, ports: list[int], timeout: float,
              batch: int, delay: float, jitter: float) -> list[int]:
    from scapy.all import IP, TCP, RandShort, sr

    open_ports: list[int] = []
    for i in range(0, len(ports), batch):
        chunk = ports[i:i + batch]
        try:
            ans, _ = sr(IP(dst=ip) / TCP(dport=chunk, sport=RandShort(), flags="S"),
                        timeout=timeout, verbose=0)
        except Exception:
            break
        for _snd, rcv in ans:
            if rcv.haslayer(TCP) and int(rcv[TCP].flags) & 0x12 == 0x12:  # SYN|ACK
                p = int(rcv[TCP].sport)
                open_ports.append(p)
                bus.emit({"type": "port", "ip": ip, "port": p,
                          "service": service_name(p), "banner": ""})
        if delay or jitter:
            time.sleep(delay + random.uniform(0, jitter))
    return sorted(set(open_ports))


async def _banner_of(ip: str, port: int, timeout: float, sem: asyncio.Semaphore) -> dict:
    async with sem:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout)
            banner = await _grab_banner(reader, writer, port, timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"port": port, "service": service_name(port), "banner": banner}
        except Exception:
            return {"port": port, "service": service_name(port), "banner": ""}


async def _syn_scan(ip: str, port_list: list[int], timeout: float,
                    grab_banner: bool, low_noise: bool) -> list[dict]:
    batch = 64 if low_noise else 512
    delay = 0.8 if low_noise else 0.0
    jitter = 0.6 if low_noise else 0.0
    bus.emit({"type": "portscan",
              "msg": f"SYN scan de {len(port_list)} puertos en {ip}"
                     f"{' (low-noise)' if low_noise else ''}..."})
    found = await asyncio.to_thread(_syn_sync, ip, port_list, timeout, batch, delay, jitter)
    if not found:
        bus.emit({"type": "portscan", "msg": f"{ip}: 0 puertos abiertos"})
        return []
    results = [{"port": p, "service": service_name(p), "banner": ""} for p in found]
    if grab_banner:
        sem = asyncio.Semaphore(8 if low_noise else 100)
        banners = await asyncio.gather(*(_banner_of(ip, p, timeout, sem) for p in found))
        by_port = {b["port"]: b["banner"] for b in banners}
        for r in results:
            r["banner"] = by_port.get(r["port"], "")
    bus.emit({"type": "portscan",
              "msg": f"{ip}: {len(results)} puertos abiertos (SYN) de {len(port_list)}"})
    return results
