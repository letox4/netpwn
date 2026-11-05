"""Bus de eventos thread-safe.

Los modulos corren en hilos (scapy) y necesitan empujar eventos hacia los
clientes conectados por WebSocket, que viven en el loop de asyncio. Este bus
hace de puente: los hilos llaman a `emit()` y el loop reparte a cada suscriptor.
"""
import asyncio
from collections import deque
from typing import Optional


class EventBus:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        # Replay: ultimos eventos para que un WS que conecta tarde vea el
        # historico reciente (p.ej. avisos de iptables residuales).
        self._replay: deque[dict] = deque(maxlen=30)

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        # Primero el historico, luego alta de suscriptor.
        for ev in self._replay:
            q.put_nowait(ev)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def emit(self, event: dict) -> None:
        """Seguro para llamar desde cualquier hilo."""
        loop = self._loop
        if loop is None:
            return
        loop.call_soon_threadsafe(self._dispatch, event)

    def _dispatch(self, event: dict) -> None:
        self._replay.append(event)
        for q in list(self._subscribers):
            # Nunca bloquear ni reventar: si la cola esta llena, se descarta
            # el evento mas viejo para hacer sitio.
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass


bus = EventBus()
