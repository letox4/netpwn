"""Registro de los modulos que estan corriendo en cada momento."""
import threading


class Manager:
    # Orden de parada: primero lo mas ruidoso/ofensivo, al final lo pasivo.
    _ORDER = ("pmkid", "handshake", "deauth", "wifi_scan", "mitm6", "wpad",
              "poison", "httpinject", "creds", "dns", "sniffer", "arp")

    def __init__(self) -> None:
        # Serializa stop+start+asignacion para que dos endpoints no pisen
        # el mismo modulo a la vez.
        self.lock = threading.Lock()
        self.arp = None
        self.sniffer = None
        self.dns = None
        self.creds = None
        self.httpinject = None
        self.wifi_scan = None
        # Clientes Wi-Fi observados pasivamente en el ultimo escaneo.
        # Se conserva al detener el scanner para poder elegir un objetivo.
        self.wifi_clients = {}
        self.deauth = None
        self.handshake = None
        self.pmkid = None
        self.poison = None
        self.wpad = None
        self.mitm6 = None

    def restart(self, attr: str, instance) -> None:
        """Para la instancia previa y registra la nueva, bajo lock."""
        with self.lock:
            prev = getattr(self, attr, None)
            if prev is not None:
                try:
                    prev.stop()
                except Exception:
                    pass
            setattr(self, attr, instance)

    def clear(self, attr: str) -> None:
        """Para y desregistra el modulo indicado, bajo lock."""
        with self.lock:
            prev = getattr(self, attr, None)
            if prev is not None:
                try:
                    prev.stop()
                except Exception:
                    pass
            setattr(self, attr, None)

    def status(self) -> dict:
        out = {}
        for name in ("arp", "sniffer", "dns", "creds", "httpinject", "wifi_scan",
                     "deauth", "handshake", "pmkid", "poison", "wpad", "mitm6"):
            module = getattr(self, name)
            # Si el objeto expone .running (p.ej. deauth), es la fuente de
            # verdad; si no, basta con saber si hay instancia.
            out[name] = bool(getattr(module, "running", module is not None))
        return out

    def stop_all(self) -> list[str]:
        stopped = []
        for name in self._ORDER:
            mod = getattr(self, name, None)
            if mod is None:
                continue
            try:
                mod.stop()
                stopped.append(name)
            except Exception:
                pass
            setattr(self, name, None)
        return stopped


manager = Manager()
