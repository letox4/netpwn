"""Reglas de firewall etiquetadas.

Toda regla que NetPwn instala lleva el comentario `netpwn`. La limpieza
(emergencia, cierre limpio o crash) borra SOLO lo nuestro consultando ese
comentario, sin tocar reglas preexistentes del sistema.
"""
import re
import subprocess

from core.bus import bus

TAG = "netpwn"

# El tag debe aparecer como comentario iptables completo (netpwn seguido de
# espacio o fin de linea), para no confundirlo con "netpwn2" ajeno.
_COMMENT_RE = re.compile(r"--comment\s+netpwn(?:\s|$)")

_BIN = {"ipv4": "iptables", "ipv6": "ip6tables"}
_TABLES = ("nat", "mangle", "filter")


def _run(binary: str, args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run([binary, *args], capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, PermissionError):
        # iptables/ip6tables no existen (p.ej. Windows/macOS o modo demo):
        # fingir "command not found" para que la limpieza siga su curso.
        return subprocess.CompletedProcess([binary, *args], 127, "", "binary not found")


def add_redirect(to_port: int, dport: int = 80, table: str = "nat",
                 chain: str = "PREROUTING", family: str = "ipv4") -> None:
    """Regla REDIRECT etiquetada (p.ej. TCP/80 de la victima -> proxy local)."""
    args = ["-t", table, "-A", chain, "-p", "tcp", "--dport", str(dport),
            "-j", "REDIRECT", "--to-port", str(to_port),
            "-m", "comment", "--comment", TAG]
    proc = _run(_BIN[family], args)
    if proc.returncode != 0:
        bus.emit({"type": "error",
                  "msg": f"{_BIN[family]} fallo: {(proc.stderr or '').strip()}"})


def _tagged_rules(family: str) -> list[tuple[str, str]]:
    """[(tabla, spec)] de las reglas actuales marcadas con el tag."""
    binary = _BIN[family]
    found = []
    for table in _TABLES:
        proc = _run(binary, ["-t", table, "-S"])
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if "--comment" in line and _COMMENT_RE.search(line):
                # "-A CADENA ..." -> "CADENA ..." (sin el -A)
                spec = line[3:] if line.startswith("-A ") else line
                found.append((table, spec))
    return found


def peek(family: str | None = None) -> int:
    """Cuenta reglas etiquetadas sin borrarlas (detectar restos de un crash)."""
    if family:
        return len(_tagged_rules(family))
    return len(_tagged_rules("ipv4")) + len(_tagged_rules("ipv6"))


def cleanup(family: str = "ipv4") -> int:
    """Elimina TODAS las reglas con el tag netpwn. Devuelve cuantas borro."""
    binary = _BIN[family]
    removed = 0
    for table, spec in _tagged_rules(family):
        proc = _run(binary, ["-t", table, "-D", *spec.split()])
        if proc.returncode == 0:
            removed += 1
    return removed


def cleanup_all() -> int:
    return cleanup("ipv4") + cleanup("ipv6")
