"""NetPwn - Suite grafica de pentesting de redes.

API FastAPI que expone cada modulo y transmite eventos en vivo por WebSocket
a la interfaz web. Pensado para ejecutarse como root en Kali Linux.
"""
import asyncio
import json
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core import demo, envcheck, netutils
from core.bus import bus
from core.cleanup import full_cleanup, register as register_cleanup
from core.manager import manager
from modules import discovery, fingerprint, opsec, portscan, topology, wifi
from modules import exploits
from modules.arp import ArpSpoofer
from modules import cameras
from modules.creds import CredSniffer
from modules.dns import DnsSpoofer
from modules.httpinject import HttpInjector
from modules.mitm6 import Mitm6
from modules.poison import NamePoisoner
from modules.sniff import Sniffer
from modules.wifi import Deauther, HandshakeCapturer, PmkidCapturer, WifiScanner
from modules.wpad import WpadSpoofer

app = FastAPI(title="NetPwn")

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"


@app.on_event("startup")
async def _startup() -> None:
    bus.bind_loop(asyncio.get_running_loop())
    register_cleanup()
    if demo.is_demo():
        # Modo demo: sin /proc, sin iptables, sin root. Solo el guion de eventos.
        bus.emit({"type": "info",
                  "msg": "NetPwn en MODO DEMO: red ficticia, modulos ofensivos desactivados"})
        asyncio.create_task(demo.timeline())
        return
    from core import fw
    from core.state import state, load as load_state
    prev = load_state()
    if prev:
        # Recuperacion tras crash: conserva los valores pre-modificacion
        # para que el PANICO restaure los originales de verdad.
        state.data.update(prev)
        state._taken = True
    else:
        state.snapshot_system()  # valor original de ip_forward para el panico
    if fw.peek():
        bus.emit({"type": "error",
                  "msg": f"Hay {fw.peek()} reglas iptables de netpwn sin limpiar "
                         f"(resto de un crash). Usa el boton de PANICO o /api/cleanup"})


# En demo, los endpoints ofensivos (que tocan sockets raw, iptables o el
# sistema) responden 400 con un mensaje claro en vez de fallar feo.
_DEMO_ALLOWED = {
    "/api/interfaces", "/api/status", "/api/discovery", "/api/portscan",
    "/api/fingerprint", "/api/exploits/check", "/api/topology",
    "/api/envcheck", "/api/cleanup", "/api/opsec/generate",
    "/api/opsec/preview", "/api/wifi/ifaces", "/api/wifi/captures",
    "/api/opsec", "/api/wifi/clients",
}


@app.middleware("http")
async def _demo_guard(request: Request, call_next):
    if demo.is_demo() and request.url.path.startswith("/api/") \
            and request.url.path not in _DEMO_ALLOWED:
        return JSONResponse(
            status_code=400,
            content={"detail": "Endpoint desactivado en modo demo "
                               "(arranca sin --demo para uso real)"})
    return await call_next(request)


# --------------------------------------------------------------------------- #
# Modelos de peticion
# --------------------------------------------------------------------------- #
class ScanReq(BaseModel):
    interface: str
    cidr: str
    timeout: float = 2.0


class PortReq(BaseModel):
    ip: str
    ports: str | list[int] | None = None
    timeout: float = 0.6
    concurrency: int = 800
    grab_banner: bool = True
    mode: str = "connect"      # "connect" | "syn" (stealth)
    low_noise: bool = False    # menos velocidad, jitter aleatorio


class FingerprintReq(BaseModel):
    ip: str
    mac: str | None = None
    open_ports: list[int] = []


class ExploitCheckReq(BaseModel):
    ip: str | None = None
    services: list[dict] = []


class CameraAuditReq(BaseModel):
    target: str                    # IP o CIDR
    port: int | None = None
    modules: list[str] = ["creds", "rtsp", "onvif"]  # creds rtsp http onvif wifi modern cloud vuln
    timeout: int = 5
    depth: int = 2                 # profundidad fuzzing HTTP
    interface: str | None = None   # solo para el modulo wifi


class CameraDiscoverReq(BaseModel):
    target: str                    # CIDR o IP
    timeout: int = 3


class TopologyReq(BaseModel):
    interface: str
    cidr: str
    aggressive: bool = False
    traffic_seconds: float = 0


class HttpInjectReq(BaseModel):
    inject: str = ""
    sslstrip: bool = True
    port: int = 8080


class WifiScanReq(BaseModel):
    interface: str
    channels: list[int] | None = None
    prepare: bool = True


class DeauthReq(BaseModel):
    interface: str
    bssid: str
    client: str | None = None
    channel: int | None = None
    prepare: bool = True
    low_noise: bool = False
    broadcast: bool = False


class PmkidReq(BaseModel):
    interface: str
    bssid: str
    channel: int | None = None
    auto_convert: bool = False
    prepare: bool = True


class PoisonReq(BaseModel):
    interface: str
    spoof_ip: str | None = None
    llmnr: bool = True
    nbtns: bool = True
    mdns: bool = True


class WpadReq(BaseModel):
    interface: str
    pac_port: int = 80
    proxy_port: int = 3128


class Mitm6Req(BaseModel):
    interface: str
    interval: float = 10.0
    jitter: float = 2.0
    mapping: dict[str, str] = {}
    redirect_http_port: int | None = None


class HandshakeReq(BaseModel):
    interface: str
    channel: int | None = None
    auto_convert: bool = False
    prepare: bool = True


class WifiMonitorReq(BaseModel):
    interface: str
    prepare: bool = True


class ConvertReq(BaseModel):
    file: str


class ArpReq(BaseModel):
    interface: str
    target_ip: str
    gateway_ip: str


class SniffReq(BaseModel):
    interface: str
    bpf: str | None = None


class DnsReq(BaseModel):
    interface: str
    mapping: dict[str, str] = {}
    spoof_all_to: str | None = None


class CredReq(BaseModel):
    interface: str


class OpsecHostReq(BaseModel):
    hostname: str
    pretty: str | None = None


class OpsecMacReq(BaseModel):
    interface: str
    mac: str | None = None
    vendor: str | None = None
    dhcp: bool = False


class OpsecApplyReq(BaseModel):
    interface: str
    hostname: str
    mac: str | None = None
    vendor: str | None = None
    pretty: str | None = None
    dhcp: bool = False


class OpsecProfileReq(BaseModel):
    interface: str
    profile: str
    dhcp: bool = False


class OpsecRestoreReq(BaseModel):
    interface: str | None = None


class OpsecGenReq(BaseModel):
    vendor: str | None = None
    kind: str = "windows"


# --------------------------------------------------------------------------- #
# Endpoints de informacion
# --------------------------------------------------------------------------- #
@app.get("/api/interfaces")
def api_interfaces():
    if demo.is_demo():
        return demo.interfaces()
    return {"interfaces": netutils.list_interfaces(), "gateway": netutils.default_gateway()}


@app.get("/api/status")
def api_status():
    return manager.status()


# --------------------------------------------------------------------------- #
# Reconocimiento
# --------------------------------------------------------------------------- #
@app.post("/api/discovery")
async def api_discovery(req: ScanReq):
    if demo.is_demo():
        await asyncio.sleep(0.8)  # teatro: simular el barrido ARP
        hosts = demo.hosts()
        # El frontend rellena la columna SO con eventos fingerprint.
        for h in demo.HOSTS:
            bus.emit({"type": "fingerprint", "ip": h["ip"], "os": h["os"],
                      "ttl": h["ttl"]})
        return {"hosts": hosts}
    # FastAPI corre las funciones sync en un threadpool, asi srp() no bloquea el loop.
    hosts = await asyncio.to_thread(discovery.scan, req.interface, req.cidr, req.timeout)
    return {"hosts": hosts}


@app.post("/api/portscan")
async def api_portscan(req: PortReq):
    if demo.is_demo():
        open_ports = demo.ports_for(req.ip)
        for p in open_ports:
            await asyncio.sleep(0.25)  # progreso en vivo, como el scan real
            bus.emit({"type": "port", "port": p["port"],
                      "service": p["service"], "banner": p["banner"]})
        return {"ip": req.ip, "open": open_ports}
    result = await portscan.scan(req.ip, req.ports, req.timeout,
                                 req.concurrency, req.grab_banner,
                                 mode=req.mode, low_noise=req.low_noise)
    return {"ip": req.ip, "open": result}


@app.post("/api/fingerprint")
async def api_fingerprint(req: FingerprintReq):
    if demo.is_demo():
        for h in demo.HOSTS:
            if h["ip"] == req.ip:
                return {"ip": h["ip"], "os": h["os"], "ttl": h["ttl"]}
        return {"ip": req.ip, "os": "?", "ttl": None}
    return await fingerprint.guess_async(req.ip, req.mac, req.open_ports)


@app.post("/api/exploits/check")
def api_exploits_check(req: ExploitCheckReq):
    try:
        results = exploits.searcher.check(req.services)
        return {"results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------------------------- #
# Camaras: auditoria integrada (port nativo de CameraAudit)
# --------------------------------------------------------------------------- #
@app.post("/api/camera/discover")
async def api_camera_discover(req: CameraDiscoverReq):
    return await asyncio.to_thread(cameras.discover, req.target, req.timeout)


@app.post("/api/camera/audit")
async def api_camera_audit(req: CameraAuditReq):
    return await cameras.audit(req.target, port=req.port, modules=req.modules,
                               timeout=req.timeout, depth=req.depth,
                               interface=req.interface)


# --------------------------------------------------------------------------- #
# Topologia de red (grafo de dispositivos)
# --------------------------------------------------------------------------- #
@app.post("/api/topology")
async def api_topology(req: TopologyReq):
    if demo.is_demo():
        await asyncio.sleep(1.0)
        return demo.TOPOLOGY
    try:
        return await topology.build(req.interface, req.cidr, req.aggressive,
                                    req.traffic_seconds)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# --------------------------------------------------------------------------- #
# MITM / ARP
# --------------------------------------------------------------------------- #
@app.post("/api/arp/start")
def api_arp_start(req: ArpReq):
    spoofer = ArpSpoofer(req.target_ip, req.gateway_ip, req.interface)
    with manager.lock:
        if manager.arp:
            manager.arp.stop()
        spoofer.start()
        manager.arp = spoofer
    return {"status": "started"}


@app.post("/api/arp/stop")
def api_arp_stop():
    if manager.arp:
        manager.arp.stop()
        manager.arp = None
    return {"status": "stopped"}


# --------------------------------------------------------------------------- #
# Sniffer
# --------------------------------------------------------------------------- #
@app.post("/api/sniff/start")
def api_sniff_start(req: SniffReq):
    sniffer = Sniffer(req.interface, req.bpf)
    with manager.lock:
        if manager.sniffer:
            manager.sniffer.stop()
        sniffer.start()
        manager.sniffer = sniffer
    return {"status": "started"}


@app.post("/api/sniff/stop")
def api_sniff_stop():
    if manager.sniffer:
        manager.sniffer.stop()
        manager.sniffer = None
    return {"status": "stopped"}


# --------------------------------------------------------------------------- #
# DNS spoofing
# --------------------------------------------------------------------------- #
@app.post("/api/dns/start")
def api_dns_start(req: DnsReq):
    spoofer = DnsSpoofer(req.interface, req.mapping, req.spoof_all_to)
    with manager.lock:
        if manager.dns:
            manager.dns.stop()
        spoofer.start()
        manager.dns = spoofer
    return {"status": "started"}


@app.post("/api/dns/stop")
def api_dns_stop():
    if manager.dns:
        manager.dns.stop()
        manager.dns = None
    return {"status": "stopped"}


# --------------------------------------------------------------------------- #
# Credenciales
# --------------------------------------------------------------------------- #
@app.post("/api/creds/start")
def api_creds_start(req: CredReq):
    sniffer = CredSniffer(req.interface)
    with manager.lock:
        if manager.creds:
            manager.creds.stop()
        sniffer.start()
        manager.creds = sniffer
    return {"status": "started"}


@app.post("/api/creds/stop")
def api_creds_stop():
    if manager.creds:
        manager.creds.stop()
        manager.creds = None
    return {"status": "stopped"}


@app.get("/api/creds/export")
def api_creds_export():
    """Descarga el buffer de credenciales como JSON. No se persiste nunca a disco."""
    creds = manager.creds.export() if manager.creds else []
    return Response(
        content=json.dumps(creds, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=creds.json"},
    )


@app.post("/api/creds/clear")
def api_creds_clear():
    if manager.creds:
        manager.creds.clear()
    return {"status": "cleared"}


# --------------------------------------------------------------------------- #
# MITM HTTP: inyeccion + sslstrip
# --------------------------------------------------------------------------- #
@app.post("/api/httpinject/start")
async def api_httpinject_start(req: HttpInjectReq):
    injector = HttpInjector(req.inject, req.sslstrip, req.port)
    with manager.lock:
        if manager.httpinject:
            manager.httpinject.stop()
        injector.start(asyncio.get_running_loop())
        manager.httpinject = injector
    return {"status": "started"}


@app.post("/api/httpinject/stop")
def api_httpinject_stop():
    if manager.httpinject:
        manager.httpinject.stop()
        manager.httpinject = None
    return {"status": "stopped"}


# --------------------------------------------------------------------------- #
# Wi-Fi: modo monitor y servicios interferentes
# --------------------------------------------------------------------------- #
def _wifi_iface(req_iface: str, prepare: bool) -> str:
    if not prepare:
        return req_iface
    try:
        info = wifi.prepare_monitor(req_iface)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return info.get("interface") or req_iface


@app.get("/api/wifi/ifaces")
def api_wifi_ifaces():
    if demo.is_demo():
        return {"interfaces": [demo.IFACE["name"]]}
    return {"interfaces": wifi.list_wireless()}


@app.post("/api/wifi/monitor/start")
def api_wifi_monitor_start(req: WifiMonitorReq):
    try:
        if req.prepare:
            return wifi.prepare_monitor(req.interface)
        return wifi.set_monitor(req.interface, True)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/wifi/monitor/stop")
def api_wifi_monitor_stop(req: WifiMonitorReq):
    try:
        result = wifi.set_monitor(req.interface, False)
        if req.prepare:
            wifi.restore_interferers()
        return result
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/wifi/kill")
def api_wifi_kill():
    return {"stopped": wifi.kill_interferers()}


@app.post("/api/wifi/restore-services")
def api_wifi_restore_services():
    return {"started": wifi.restore_interferers()}


# --------------------------------------------------------------------------- #
# Wi-Fi: escaneo 802.11 y deauth
# --------------------------------------------------------------------------- #
@app.post("/api/wifi/scan/start")
def api_wifi_scan_start(req: WifiScanReq):
    iface = _wifi_iface(req.interface, req.prepare)
    scanner = WifiScanner(iface, req.channels)
    manager.wifi_clients = scanner.clients
    with manager.lock:
        if manager.wifi_scan:
            manager.wifi_scan.stop()
        scanner.start()
        manager.wifi_scan = scanner
    return {"status": "started", "interface": iface}


@app.post("/api/wifi/scan/stop")
def api_wifi_scan_stop():
    if manager.wifi_scan:
        manager.wifi_scan.stop()
        manager.wifi_scan = None
    return {"status": "stopped"}


@app.get("/api/wifi/clients")
def api_wifi_clients(bssid: str | None = None):
    if demo.is_demo():
        return {"clients": []}
    now = time.time()
    wanted = bssid.lower() if bssid else None
    clients = []
    for (ap, client), info in list(manager.wifi_clients.items()):
        age = max(0, now - info.get("last_seen", 0))
        if age > 120 or (wanted and ap != wanted):
            continue
        clients.append({**info, "age": round(age, 1)})
    return {"clients": sorted(clients, key=lambda c: (c["bssid"], c["client"]))}


@app.post("/api/wifi/deauth/start")
def api_wifi_deauth_start(req: DeauthReq):
    bssid = req.bssid.strip().lower()
    client = req.client.strip().lower() if req.client else None
    if not wifi.is_unicast_mac(bssid):
        raise HTTPException(status_code=400, detail="BSSID invalido")
    if req.broadcast:
        if client and client != "ff:ff:ff:ff:ff:ff":
            raise HTTPException(status_code=400, detail="No combines modo broadcast con un cliente individual")
        client = "ff:ff:ff:ff:ff:ff"
    else:
        if not wifi.is_unicast_mac(client):
            raise HTTPException(status_code=400,
                                detail="Selecciona un cliente detectado o activa explicitamente el modo broadcast")
        if bssid == client:
            raise HTTPException(status_code=400, detail="El cliente objetivo no puede ser el BSSID del AP")
        observed = manager.wifi_clients.get((bssid, client))
        if not observed or time.time() - observed.get("last_seen", 0) > 120:
            raise HTTPException(status_code=400,
                                detail="Cliente no detectado recientemente en ese AP. Ejecuta primero el escaneo Wi-Fi.")
    # El scanner salta de canal; detenlo antes de fijar el canal del objetivo.
    if manager.wifi_scan:
        manager.wifi_scan.stop()
        manager.wifi_scan = None
    iface = _wifi_iface(req.interface, req.prepare)
    try:
        deauther = Deauther(iface, bssid, client, req.channel,
                            low_noise=req.low_noise, broadcast=req.broadcast)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    with manager.lock:
        if manager.deauth:
            manager.deauth.stop()
        deauther.start()
        manager.deauth = deauther
    return {"status": "started", "interface": iface}


@app.post("/api/wifi/deauth/stop")
def api_wifi_deauth_stop():
    if manager.deauth:
        manager.deauth.stop()
        manager.deauth = None
    return {"status": "stopped"}


# --------------------------------------------------------------------------- #
# Wi-Fi: captura de handshakes EAPOL y conversion a hashcat
# --------------------------------------------------------------------------- #
@app.post("/api/wifi/handshake/start")
def api_handshake_start(req: HandshakeReq):
    # El scanner salta de canal; detenlo antes de fijar el canal del objetivo.
    if manager.wifi_scan:
        manager.wifi_scan.stop()
        manager.wifi_scan = None
    iface = _wifi_iface(req.interface, req.prepare)
    capturer = HandshakeCapturer(iface, req.channel, req.auto_convert)
    with manager.lock:
        if manager.handshake:
            manager.handshake.stop()
        capturer.start()
        manager.handshake = capturer
    return {"status": "started", "interface": iface}


@app.post("/api/wifi/handshake/stop")
def api_handshake_stop():
    if manager.handshake:
        manager.handshake.stop()
        manager.handshake = None
    return {"status": "stopped"}


# --------------------------------------------------------------------------- #
# Wi-Fi: captura de PMKID (sin cliente, sin deauth)
# --------------------------------------------------------------------------- #
@app.post("/api/wifi/pmkid/start")
def api_pmkid_start(req: PmkidReq):
    # El scanner salta de canal; detenlo antes de fijar el canal del objetivo.
    if manager.wifi_scan:
        manager.wifi_scan.stop()
        manager.wifi_scan = None
    iface = _wifi_iface(req.interface, req.prepare)
    capturer = PmkidCapturer(iface, req.bssid, req.channel, req.auto_convert)
    with manager.lock:
        if manager.pmkid:
            manager.pmkid.stop()
        capturer.start()
        manager.pmkid = capturer
    return {"status": "started", "interface": iface}


@app.post("/api/wifi/pmkid/stop")
def api_pmkid_stop():
    if manager.pmkid:
        manager.pmkid.stop()
        manager.pmkid = None
    return {"status": "stopped"}


@app.get("/api/wifi/captures")
def api_wifi_captures():
    return {"captures": wifi.list_captures()}


@app.post("/api/wifi/convert")
def api_wifi_convert(req: ConvertReq):
    pcap = wifi.CAPTURE_DIR / Path(req.file).name
    if not pcap.exists():
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    try:
        return wifi.convert_to_22000(pcap)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/wifi/download")
def api_wifi_download(file: str):
    path = wifi.CAPTURE_DIR / Path(file).name
    if not (path.resolve().is_relative_to(wifi.CAPTURE_DIR.resolve())
            and path.is_file()):
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    return FileResponse(path, filename=path.name, media_type="application/octet-stream")


# --------------------------------------------------------------------------- #
# Poisoners: LLMNR / NBT-NS / mDNS
# --------------------------------------------------------------------------- #
@app.post("/api/poison/start")
def api_poison_start(req: PoisonReq):
    poisoner = NamePoisoner(req.interface, req.spoof_ip,
                            req.llmnr, req.nbtns, req.mdns)
    with manager.lock:
        if manager.poison:
            manager.poison.stop()
        poisoner.start()
        manager.poison = poisoner
    return {"status": "started"}


@app.post("/api/poison/stop")
def api_poison_stop():
    if manager.poison:
        manager.poison.stop()
        manager.poison = None
    return {"status": "stopped"}


# --------------------------------------------------------------------------- #
# WPAD: PAC + proxy que registra
# --------------------------------------------------------------------------- #
def _iface_ip(iface_name: str) -> str:
    for i in netutils.list_interfaces():
        if i["name"] == iface_name and i.get("ip"):
            return i["ip"]
    raise HTTPException(status_code=400,
                        detail="La interfaz no tiene IPv4 (necesaria para WPAD)")


@app.post("/api/wpad/start")
def api_wpad_start(req: WpadReq):
    spoofer = WpadSpoofer(_iface_ip(req.interface), req.pac_port, req.proxy_port)
    with manager.lock:
        if manager.wpad:
            manager.wpad.stop()
        spoofer.start()
        manager.wpad = spoofer
    return {"status": "started"}


@app.post("/api/wpad/stop")
def api_wpad_stop():
    if manager.wpad:
        manager.wpad.stop()
        manager.wpad = None
    return {"status": "stopped"}


# --------------------------------------------------------------------------- #
# mitm6: RA + DNS spoofing IPv6
# --------------------------------------------------------------------------- #
@app.post("/api/mitm6/start")
def api_mitm6_start(req: Mitm6Req):
    if manager.mitm6:
        manager.mitm6.stop()
    try:
        attacker = Mitm6(req.interface, req.interval, req.jitter,
                         req.mapping, req.redirect_http_port)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    with manager.lock:
        if manager.mitm6:
            manager.mitm6.stop()
        attacker.start()
        manager.mitm6 = attacker
    return {"status": "started"}


@app.post("/api/mitm6/stop")
def api_mitm6_stop():
    if manager.mitm6:
        manager.mitm6.stop()
        manager.mitm6 = None
    return {"status": "stopped"}


# --------------------------------------------------------------------------- #
# OPSEC: hostname + MAC
# --------------------------------------------------------------------------- #
def _opsec_or_400(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/opsec")
def api_opsec_identity():
    if demo.is_demo():
        iface = dict(demo.IFACE)
        return {
            "hostname": "netpwn-demo", "pretty": None, "original_hostname": None,
            "spoofed": False,
            "interfaces": [{"name": iface["name"], "mac": iface["mac"],
                            "permanent": iface["mac"], "spoofed": False}],
            "vendors": [], "profiles": [],
        }
    return opsec.identity()


@app.post("/api/opsec/preview")
def api_opsec_preview(req: OpsecProfileReq):
    return _opsec_or_400(opsec.preview_profile, req.profile)


@app.post("/api/opsec/generate")
def api_opsec_generate(req: OpsecGenReq):
    return {
        "hostname": opsec.generate_hostname(req.kind),
        **opsec.generate_mac(req.vendor),
    }


@app.post("/api/opsec/hostname")
def api_opsec_hostname(req: OpsecHostReq):
    return _opsec_or_400(opsec.set_hostname, req.hostname, req.pretty)


@app.post("/api/opsec/mac")
def api_opsec_mac(req: OpsecMacReq):
    return _opsec_or_400(opsec.set_mac, req.interface, req.mac, req.vendor, req.dhcp)


@app.post("/api/opsec/apply")
def api_opsec_apply(req: OpsecApplyReq):
    return _opsec_or_400(
        opsec.apply_identity, req.interface, req.hostname,
        req.mac, req.vendor, req.pretty, req.dhcp,
    )


@app.post("/api/opsec/profile")
def api_opsec_profile(req: OpsecProfileReq):
    return _opsec_or_400(opsec.apply_profile, req.interface, req.profile, req.dhcp)


@app.post("/api/opsec/restore")
def api_opsec_restore(req: OpsecRestoreReq):
    return _opsec_or_400(opsec.restore, req.interface)


# --------------------------------------------------------------------------- #
# Emergencias y entorno
# --------------------------------------------------------------------------- #
@app.post("/api/panic")
def api_panic():
    """Kill switch: para TODO, borra reglas etiquetadas y restaura identidad."""
    actions = full_cleanup("boton de panico")
    return {"status": "panicked", "actions": actions}


@app.get("/api/cleanup")
def api_cleanup_status():
    from core import fw
    return {"tagged_rules": fw.peek()}


@app.post("/api/cleanup")
def api_cleanup_run():
    from core import fw
    return {"removed": fw.cleanup_all()}


@app.get("/api/envcheck")
def api_envcheck():
    if demo.is_demo():
        return {"warnings": demo.envcheck()}
    return {"warnings": envcheck.check()}


# --------------------------------------------------------------------------- #
# WebSocket de eventos en vivo
# --------------------------------------------------------------------------- #
@app.websocket("/ws")
async def ws_events(websocket: WebSocket):
    await websocket.accept()
    queue = bus.subscribe()
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception:
        # Cliente ido o conexion rota de forma inesperada: solo cerrar limpio.
        pass
    finally:
        bus.unsubscribe(queue)


@app.on_event("shutdown")
async def _shutdown() -> None:
    if demo.is_demo():
        return
    full_cleanup("apagado")


# --------------------------------------------------------------------------- #
# Frontend estatico
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
