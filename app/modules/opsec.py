"""Identidad de la maquina para OPSEC en pentests autorizados.

Cambia hostname y MAC de una interfaz, guarda los valores originales y
permite restaurarlos. Las MAC se generan con OUI de fabricantes reales
(bit U/L = 0) para no delatar una direccion 'locally administered'.
"""
import json
import os
import random
import re
import shutil
import socket
import subprocess
from pathlib import Path

from core.bus import bus

STATE_PATH = Path(__file__).resolve().parent.parent.parent / ".opsec_state.json"

# OUI publicos conocidos. El resto de la MAC se randomiza.
VENDORS = {
    "Dell": ["18:66:DA", "D4:BE:D9", "84:7B:EB", "F8:B1:56"],
    "HP": ["3C:D9:2B", "94:57:A5", "9C:8E:99", "00:1E:0B"],
    "Lenovo": ["54:EE:75", "98:FA:9B", "28:D2:44"],
    "Intel": ["3C:97:0E", "00:1B:21", "A0:36:9F", "00:1E:65"],
    "Apple": ["AC:87:A3", "F0:18:98", "A4:83:E7", "00:1C:B3"],
    "Samsung": ["8C:F5:A3", "C8:19:F7", "F4:09:D8"],
    "Cisco": ["00:1A:A1", "00:1B:54", "68:BD:AB"],
    "Realtek": ["00:E0:4C", "00:05:1B"],
}

_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except FileNotFoundError:
        # Binario no instalado en esta imagen: devolvemos fallo controlado
        # en vez de reventar el endpoint (pasa con dhclient, ethtool...).
        return subprocess.CompletedProcess(cmd, returncode=127, stdout="", stderr="no encontrado")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, returncode=124, stdout="",
                                           stderr="timeout")


def _load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"hostname": None, "pretty": None, "macs": {}}


def _save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def current_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return ""


def current_pretty() -> str:
    proc = _run(["hostnamectl", "--pretty"])
    if proc.returncode == 0:
        return (proc.stdout or "").strip()
    return ""


def current_mac(iface: str) -> str | None:
    path = Path(f"/sys/class/net/{iface}/address")
    if path.exists():
        return path.read_text().strip()
    return None


def permanent_mac(iface: str) -> str | None:
    """MAC de fabrica si ethtool la conoce; si no, la que guardamos al primer cambio."""
    proc = _run(["ethtool", "-P", iface])
    if proc.returncode == 0:
        # "Permanent address: aa:bb:cc:dd:ee:ff"
        for part in proc.stdout.replace("\n", " ").split():
            if _MAC_RE.match(part):
                if not part.lower().startswith("00:00:00"):
                    return part.lower()
    state = _load_state()
    saved = state.get("macs", {}).get(iface, {}).get("original")
    return saved


def list_link_interfaces() -> list[dict]:
    base = Path("/sys/class/net")
    if not base.is_dir():
        return []
    result = []
    for name in sorted(os.listdir(base)):
        if name == "lo":
            continue
        mac = current_mac(name)
        perm = permanent_mac(name)
        result.append({
            "name": name,
            "mac": mac,
            "permanent": perm,
            "spoofed": bool(mac and perm and mac.lower() != perm.lower()),
        })
    return result


def _remember_originals(iface: str | None = None) -> dict:
    state = _load_state()
    if not state.get("hostname"):
        state["hostname"] = current_hostname()
        state["pretty"] = current_pretty()
    if iface:
        macs = state.setdefault("macs", {})
        if iface not in macs:
            macs[iface] = {
                "original": permanent_mac(iface) or current_mac(iface),
            }
    _save_state(state)
    return state


def generate_mac(vendor: str | None = None) -> dict:
    name = vendor if vendor in VENDORS else random.choice(list(VENDORS))
    oui = random.choice(VENDORS[name])
    tail = [f"{random.randint(0, 255):02X}" for _ in range(3)]
    mac = ":".join(oui.split(":") + tail)
    return {"mac": mac.lower(), "vendor": name}


def generate_hostname(kind: str = "windows") -> str:
    if kind == "windows":
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return "DESKTOP-" + "".join(random.choice(alphabet) for _ in range(7))
    if kind == "macos":
        return random.choice(["MacBook-Pro", "MacBook-Air", "iMac-Office"])
    if kind == "printer":
        return "NPI" + "".join(f"{random.randint(0, 255):02X}" for _ in range(3))
    if kind == "android":
        return "android-" + "".join(f"{random.randint(0, 255):02x}" for _ in range(3))
    if kind == "corp":
        return f"LT-{random.randint(1000, 9999)}"
    return "host-" + "".join(f"{random.randint(0, 255):02x}" for _ in range(3))


PROFILES = [
    {
        "id": "windows-dell",
        "label": "Portatil Windows (Dell)",
        "blurb": "El clasico en una LAN corporativa.",
        "kind": "windows",
        "vendor": "Dell",
        "pretty": "DESKTOP",
    },
    {
        "id": "windows-lenovo",
        "label": "Portatil Windows (Lenovo)",
        "blurb": "ThinkPad generico de empleado.",
        "kind": "windows",
        "vendor": "Lenovo",
        "pretty": "DESKTOP",
    },
    {
        "id": "macos",
        "label": "MacBook",
        "blurb": "Hostname y OUI de Apple.",
        "kind": "macos",
        "vendor": "Apple",
        "pretty": "MacBook Pro",
    },
    {
        "id": "printer",
        "label": "Impresora HP",
        "blurb": "Poco sospechosa en un segmento de oficina.",
        "kind": "printer",
        "vendor": "HP",
        "pretty": "HP Printer",
    },
    {
        "id": "android",
        "label": "Movil Samsung",
        "blurb": "Cliente BYOD / invitados.",
        "kind": "android",
        "vendor": "Samsung",
        "pretty": "Galaxy",
    },
    {
        "id": "corp",
        "label": "Portatil corporativo",
        "blurb": "Nombre tipo LT-4821 + Intel.",
        "kind": "corp",
        "vendor": "Intel",
        "pretty": "Laptop",
    },
]


def preview_profile(profile_id: str) -> dict:
    profile = next((p for p in PROFILES if p["id"] == profile_id), None)
    if not profile:
        raise ValueError(f"Perfil desconocido: {profile_id}")
    mac = generate_mac(profile["vendor"])
    host = generate_hostname(profile["kind"])
    return {
        "profile": profile["id"],
        "hostname": host,
        "pretty": profile["pretty"],
        **mac,
    }


def identity() -> dict:
    state = _load_state()
    host = current_hostname()
    original = state.get("hostname")
    return {
        "hostname": host,
        "pretty": current_pretty(),
        "original_hostname": original,
        "spoofed": bool(original and original != host),
        "interfaces": list_link_interfaces(),
        "vendors": list(VENDORS),
        "profiles": PROFILES,
    }


def set_hostname(name: str, pretty: str | None = None) -> dict:
    name = (name or "").strip()
    if not _HOST_RE.match(name):
        raise ValueError("Hostname invalido. Usa letras, numeros y guiones (max 63).")
    _remember_originals()
    errors = []
    proc = _run(["hostnamectl", "set-hostname", name])
    if proc.returncode != 0:
        # Fallback sin systemd
        try:
            Path("/etc/hostname").write_text(name + "\n")
        except Exception as e:
            errors.append(str(e))
        proc2 = _run(["hostname", name])
        if proc2.returncode != 0:
            errors.append((proc.stderr or proc2.stderr or "").strip() or "hostname fallo")
    if pretty:
        _run(["hostnamectl", "set-hostname", "--pretty", pretty])
    _patch_hosts(name)
    bus.emit({"type": "opsec", "msg": f"Hostname -> {name}"})
    if errors:
        raise RuntimeError("; ".join(errors))
    return identity()


def _patch_hosts(new_name: str) -> None:
    """Kali usa 127.0.1.1 <hostname> en /etc/hosts; si no se actualiza, sudo se queja."""
    path = Path("/etc/hosts")
    if not path.exists():
        return
    try:
        lines = path.read_text().splitlines()
    except Exception:
        return
    out = []
    patched = False
    for line in lines:
        if line.startswith("127.0.1.1"):
            out.append(f"127.0.1.1\t{new_name}")
            patched = True
        else:
            out.append(line)
    if not patched:
        out.append(f"127.0.1.1\t{new_name}")
    try:
        path.write_text("\n".join(out) + "\n")
    except Exception:
        pass


def renew_dhcp(iface: str) -> None:
    """Renueva la concesion DHCP tras cambiar la MAC. Prueba dhclient, dhcpcd
    y NetworkManager (el cliente interno de Kali moderno). Nunca revienta:
    si no hay forma de renovar, solo avisa."""
    try:
        if shutil.which("dhclient"):
            _run(["dhclient", "-r", iface])
            if _run(["dhclient", iface]).returncode == 0:
                return
        elif shutil.which("dhcpcd"):
            _run(["dhcpcd", "-k", iface])
            if _run(["dhcpcd", iface]).returncode == 0:
                return
        if shutil.which("nmcli"):
            _run(["nmcli", "device", "disconnect", iface])
            if _run(["nmcli", "device", "connect", iface]).returncode == 0:
                return
    except FileNotFoundError as e:
        bus.emit({"type": "error", "msg": f"Renovando DHCP: {e}"})
    bus.emit({"type": "opsec", "msg": f"MAC cambiada; DHCP no se renovo solo ({iface})"})


def set_mac(iface: str, mac: str | None = None, vendor: str | None = None,
            dhcp: bool = False) -> dict:
    if not iface or "/" in iface or iface == "lo":
        raise ValueError("Interfaz invalida")
    if not Path(f"/sys/class/net/{iface}").exists():
        raise ValueError(f"No existe la interfaz {iface}")
    if mac:
        mac = mac.strip().lower()
        if not _MAC_RE.match(mac):
            raise ValueError("MAC invalida. Formato aa:bb:cc:dd:ee:ff")
        vendor_name = vendor or "?"
    else:
        gen = generate_mac(vendor)
        mac, vendor_name = gen["mac"], gen["vendor"]
    _remember_originals(iface)
    # Bajar, cambiar, subir. El enlace se cae un segundo. try/finally:
    # si algo falla, la interfaz vuelve a quedar UP.
    try:
        for cmd in (
            ["ip", "link", "set", iface, "down"],
            ["ip", "link", "set", iface, "address", mac],
        ):
            proc = _run(cmd)
            if proc.returncode != 0:
                raise RuntimeError((proc.stderr or proc.stdout or "ip link fallo").strip())
    finally:
        _run(["ip", "link", "set", iface, "up"])
    if dhcp:
        renew_dhcp(iface)
    bus.emit({"type": "opsec", "msg": f"MAC {iface} -> {mac} ({vendor_name})"})
    return identity()


def apply_identity(iface: str, hostname: str, mac: str | None = None,
                   vendor: str | None = None, pretty: str | None = None,
                   dhcp: bool = False) -> dict:
    set_hostname(hostname, pretty)
    set_mac(iface, mac, vendor, dhcp)
    return identity()


def apply_profile(iface: str, profile_id: str, dhcp: bool = False) -> dict:
    preview = preview_profile(profile_id)
    return apply_identity(
        iface,
        preview["hostname"],
        preview["mac"],
        preview["vendor"],
        preview.get("pretty"),
        dhcp,
    )


def restore(iface: str | None = None) -> dict:
    state = _load_state()
    errors = []
    original_host = state.get("hostname")
    if original_host:
        try:
            set_hostname(original_host, state.get("pretty") or None)
        except Exception as e:
            errors.append(str(e))
    macs = state.get("macs", {})
    targets = [iface] if iface else list(macs)
    for name in targets:
        original = macs.get(name, {}).get("original")
        if not original:
            continue
        try:
            # No re-guardar el spoof como original. try/finally para dejar
            # la interfaz UP aunque algo falle a mitad.
            try:
                for cmd in (
                    ["ip", "link", "set", name, "down"],
                    ["ip", "link", "set", name, "address", original],
                ):
                    proc = _run(cmd)
                    if proc.returncode != 0:
                        raise RuntimeError((proc.stderr or "").strip())
            finally:
                _run(["ip", "link", "set", name, "up"])
            bus.emit({"type": "opsec", "msg": f"MAC {name} restaurada ({original})"})
        except Exception as e:
            errors.append(f"{name}: {e}")
    if original_host:
        state["hostname"] = None
        state["pretty"] = None
    if iface:
        state.get("macs", {}).pop(iface, None)
    else:
        state["macs"] = {}
    _save_state(state)
    if errors:
        raise RuntimeError("; ".join(errors))
    bus.emit({"type": "opsec", "msg": "Identidad original restaurada"})
    return identity()
