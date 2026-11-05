"""Limpieza automatica: atexit + senales + boton de panico.

Da igual si cierras la terminal, matas el proceso o se cae: todo lo que
NetPwn dejo activo (spoofers, iptables, ip_forward, identidad OPSEC) se
deshace. `full_cleanup` es idempotente y se puede llamar las veces que haga
falta.
"""
import atexit
import signal
import sys

from core.bus import bus
from core import fw

_registered = False


def full_cleanup(reason: str = "salida") -> list[str]:
    """Detiene modulos, borra reglas etiquetadas y restaura el sistema."""
    from core.manager import manager  # import tardio para evitar ciclos
    from core.state import state

    actions: list[str] = []
    try:
        stopped = manager.stop_all()
        actions.append("modulos detenidos: " + (", ".join(stopped) or "ninguno"))
    except Exception as e:
        actions.append(f"error deteniendo modulos: {e}")
    actions.append(f"{fw.cleanup('ipv4')} reglas iptables eliminadas")
    actions.append(f"{fw.cleanup('ipv6')} reglas ip6tables eliminadas")
    try:
        # Identidad OPSEC (hostname + MACs), que tambien parchea /etc/hosts.
        from modules import opsec
        opsec.restore()
        actions.append("identidad OPSEC restaurada")
    except Exception:
        pass  # sin cambios de identidad pendientes
    try:
        actions.extend(state.restore()["restored"])
    except Exception as e:
        actions.append(f"error restaurando estado: {e}")
    try:
        bus.emit({"type": "cleanup", "msg": f"Limpieza ({reason}): " + "; ".join(actions)})
    except Exception:
        pass
    return actions


def register() -> None:
    """Registra atexit + SIGINT/SIGTERM. Llamar una vez al arrancar."""
    global _registered
    if _registered:
        return
    _registered = True

    def _handler(signum, _frame):
        full_cleanup(f"senal {signal.Signals(signum).name}")
        sys.exit(0)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass
    atexit.register(full_cleanup, "atexit")
