"""Snapshot del sistema para el boton de panico y la limpieza automatica.

Guarda hostname, ip_forward (v4/v6) y MACs originales ANTES de que NetPwn
toque nada, y los restaura bajo demanda. Se persiste en JSON para poder
recuperarse incluso si el proceso murio sin limpiar.
"""
import json
import subprocess
from pathlib import Path

from core import fw

STATE_FILE = Path("/var/lib/netpwn/state.json")


def load() -> dict | None:
    """Lee el JSON persistido y devuelve el dict (None si falta o falla)."""
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text())
    except Exception:
        pass
    return None


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except Exception:
        return None


class State:
    def __init__(self) -> None:
        self.data: dict = {}
        self._taken = False

    # ------------------------------------------------------------------ snapshot
    def snapshot_system(self) -> None:
        """Captura (una sola vez) valores globales antes de modificar nada."""
        if self._taken:
            return
        self.data["hostname"] = _read("/proc/sys/kernel/hostname")
        self.data["ip_forward_v4"] = _read("/proc/sys/net/ipv4/ip_forward")
        self.data["ip_forward_v6"] = _read("/proc/sys/net/ipv6/conf/all/forwarding")
        self._taken = True
        self.persist()

    def snapshot_mac(self, iface: str) -> None:
        """Guarda la MAC de fabrica de una interfaz antes de spoofearla."""
        mac = _read(f"/sys/class/net/{iface}/address")
        if mac and iface not in self.data.get("macs", {}):
            self.data.setdefault("macs", {})[iface] = mac
            self.persist()

    # ------------------------------------------------------------------ restore
    def restore(self) -> dict:
        actions: list[str] = []
        for iface, mac in self.data.get("macs", {}).items():
            for cmd in (["ip", "link", "set", iface, "down"],
                        ["ip", "link", "set", iface, "address", mac],
                        ["ip", "link", "set", iface, "up"]):
                _run(cmd)
            actions.append(f"MAC {iface} -> {mac}")
        for key, path, label in (
            ("ip_forward_v4", "/proc/sys/net/ipv4/ip_forward", "ip_forward"),
            ("ip_forward_v6", "/proc/sys/net/ipv6/conf/all/forwarding", "ipv6 forwarding"),
        ):
            val = self.data.get(key)
            if val is not None:
                try:
                    Path(path).write_text(val + "\n")
                    actions.append(f"{label} -> {val}")
                except Exception:
                    pass
        host = self.data.get("hostname")
        if host:
            if _run(["hostnamectl", "set-hostname", host]).returncode != 0:
                _run(["hostname", host])
            actions.append(f"hostname -> {host}")
        removed = fw.cleanup_all()
        actions.append(f"{removed} reglas de firewall eliminadas")
        return {"restored": actions}

    # ------------------------------------------------------------------ persist
    def persist(self) -> None:
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            STATE_FILE.write_text(json.dumps(self.data, indent=2))
        except Exception:
            pass

    @classmethod
    def load(cls) -> "State":
        st = cls()
        try:
            if STATE_FILE.exists():
                st.data = json.loads(STATE_FILE.read_text())
                st._taken = True
        except Exception:
            pass
        return st


state = State()
