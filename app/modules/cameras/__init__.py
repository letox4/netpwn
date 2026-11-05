"""Auditoria de camaras IP/CCTV integrada en NetPwn (port nativo de CameraAudit).

Los modulos auditadores (rtsp, creds, onvif, p2p/tuya, cloud recon, CVEs de
firmware) viven aqui dentro como codigo de la suite. Nada de CLI externo: este
orquestador importa las clases directamente, captura sus mensajes de terminal
y los emite por el bus de eventos WebSocket a la interfaz.

Solo para auditorias autorizadas.
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import sys
import threading
from pathlib import Path
from typing import Any

from core.bus import bus

from . import (cloud_dns_recon, credential_tester, discovery, firmware_vuln_check,
               http_fuzzer, modern_cameras, onvif_auditor, rtsp_auditor,
               wifi_auditor)

# Nombre de modulo -> (clase, requiere_target_valido)
_AUDITORS: dict[str, type] = {
    "creds": credential_tester.CredentialTester,
    "rtsp": rtsp_auditor.RTSPAuditor,
    "http": http_fuzzer.HTTPFuzzer,
    "onvif": onvif_auditor.ONVIFAuditor,
    "wifi": wifi_auditor.WiFiAuditor,
    "modern": modern_cameras.ModernCameraAuditor,
    "cloud": cloud_dns_recon.CloudDNSRecon,
    "vuln": firmware_vuln_check.FirmwareVulnChecker,
}

_MODULE_LABELS = {
    "creds": "credenciales por defecto",
    "rtsp": "RTSP",
    "http": "fuzzing HTTP",
    "onvif": "ONVIF",
    "wifi": "protocolos P2P/Tuya/MQTT",
    "modern": "camaras modernas (Tapo/Wyze/Eufy/Ring)",
    "cloud": "recon de clouds",
    "vuln": "firmware + CVEs",
}


class _BusWriter(io.TextIOBase):
    """Captura los print() de los modulos y los manda al bus de eventos."""

    def __init__(self, target: str):
        self.target = target

    def write(self, s: str) -> int:
        original = s.strip()
        if original:
            shown = original[:400] + "..." if len(original) > 400 else original
            bus.emit({"type": "camera", "msg": shown})
        return len(original)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


# redirect_stdout es global: dos auditorias concurrentes no pueden
# intercalar sus capturas.
_STDOUT_LOCK = threading.Lock()


def discover(target: str, timeout: int = 3) -> list[dict[str, Any]]:
    """Descubre camaras en la red (target: CIDR o IP)."""
    buf = _BusWriter(target)
    with _STDOUT_LOCK:
        with contextlib.redirect_stdout(buf):
            cams = discovery.CameraDiscovery(target, timeout=timeout, verbose=1).scan()
    cams = cams if isinstance(cams, list) else [cams]
    for cam in cams:
        bus.emit({"type": "camera", "found": cam})
    return cams


def _run_audit_sync(target: str, port: int | None, modules: list[str],
                    timeout: int, depth: int = 2,
                    interface: str | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    errors: list[str] = []

    buf = _BusWriter(target)
    with _STDOUT_LOCK:
        with contextlib.redirect_stdout(buf):
            for mod in modules:
                cls = _AUDITORS.get(mod)
                if cls is None:
                    errors.append(f"modulo desconocido: {mod}")
                    continue
                label = _MODULE_LABELS.get(mod, mod)
                bus.emit({"type": "camera", "msg": f"### Modulo: {label} ###"})
                try:
                    if mod == "rtsp":
                        inst = cls(target, port=port or 554, timeout=timeout, verbose=1)
                    elif mod in ("http", "onvif"):
                        inst = cls(target, port=port or 80, timeout=timeout,
                                   verbose=1, **({"depth": depth} if mod == "http" else {}))
                    elif mod == "creds":
                        inst = cls(target, port=port, timeout=timeout, verbose=1)
                    else:  # wifi, modern, cloud, vuln
                        inst = cls(target, port=port, timeout=timeout, verbose=1,
                                   **({"interface": interface} if mod == "wifi" else {}))
                    res = inst.run()
                    if not isinstance(res, list):
                        res = [res]
                    findings.extend(res)
                    bus.emit({"type": "camera",
                              "module_done": mod,
                              "n": len(res)})
                except Exception as e:  # un modulo no debe tirar el audit entero
                    errors.append(f"{mod}: {type(e).__name__}: {e}")
                    bus.emit({"type": "camera", "msg": f"[!] {mod} fallo: {e}"})

    # ordena por severidad
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.get("severity", "info"), 9))
    for f in findings:
        bus.emit({"type": "camera", "finding": f})

    result = {"target": target, "findings": findings, "errors": errors}
    bus.emit({"type": "camera", "audit_done": result})
    return result


async def audit(target: str, port: int | None = None, modules: list[str] | None = None,
                timeout: int = 5, depth: int = 2,
                interface: str | None = None) -> dict[str, Any]:
    """Corre los modulos seleccionados en un hilo (bloqueante -> hilo aparte)."""
    modules = modules or ["creds", "rtsp", "onvif"]
    return await asyncio.to_thread(
        _run_audit_sync, target, port, modules, timeout, depth, interface
    )


def is_wordlist_available() -> bool:
    return (Path(__file__).parent / "wordlists").exists()
