"""Deteccion de entorno: avisos tempranos antes de hacer nada ruidoso."""
import os
import subprocess

from core import fw

# Procesos que suelen indicar monitorizacion/deteccion en la red o el host.
_DETECTORS = ("arpwatch", "zeek", "suricata", "snort", "ossec", "p0f", "bro")


def _proc_names() -> str:
    try:
        out = subprocess.run(["ps", "-eo", "comm"], capture_output=True, text=True)
        return (out.stdout or "").lower()
    except Exception:
        return ""


def _read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return ""


def check() -> list[dict]:
    warns: list[dict] = []

    root = os.geteuid() == 0 if hasattr(os, "geteuid") else True
    if root:
        warns.append({"level": "ok", "msg": "Ejecutando como root"})
    else:
        warns.append({"level": "error",
                      "msg": "Sin root: los sockets raw e iptables no funcionaran"})

    host = _read("/proc/sys/kernel/hostname").lower()
    if host in ("kali", "kali-linux", "parrot", "attacker"):
        warns.append({"level": "warn",
                      "msg": f"Hostname '{host}' te delata en DHCP/ARP (usa el panel OPSEC)"})

    fwd = _read("/proc/sys/net/ipv4/ip_forward")
    if fwd == "1":
        warns.append({"level": "warn",
                      "msg": "ip_forward ya esta activo (quien lo dejo? revisa el boton de panico)"})

    leftovers = fw.peek()
    if leftovers:
        warns.append({"level": "warn",
                      "msg": f"{leftovers} reglas iptables de netpwn sin limpiar (resto de un crash)"})

    procs = _proc_names()
    for det in _DETECTORS:
        if det in procs:
            warns.append({"level": "warn",
                          "msg": f"'{det}' esta corriendo: puede detectar spoofing/escaneos"})

    return warns
