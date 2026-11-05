"""Tests del bus de eventos: emision thread-safe, replay y suscripciones."""
import asyncio

from core.bus import EventBus


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_emit_llega_al_suscriptor():
    async def scenario():
        bus = EventBus()
        bus.bind_loop(asyncio.get_running_loop())
        q = bus.subscribe()
        bus.emit({"type": "packet", "proto": "TCP"})
        await asyncio.sleep(0)  # deja pasar el call_soon_threadsafe
        assert await q.get() == {"type": "packet", "proto": "TCP"}

    _run(scenario())


def test_replay_entrega_historico_al_conectar_tarde():
    async def scenario():
        bus = EventBus()
        bus.bind_loop(asyncio.get_running_loop())
        q1 = bus.subscribe()
        bus.emit({"type": "error", "msg": "aviso previo"})
        await asyncio.sleep(0)
        await q1.get()  # consumido por el primero

        q2 = bus.subscribe()  # conecta despues: debe ver el replay
        assert await asyncio.wait_for(q2.get(), 1) == {"type": "error", "msg": "aviso previo"}

    _run(scenario())


def test_emit_sin_loop_no_explota():
    bus = EventBus()  # bind_loop nunca llamado
    bus.emit({"type": "x"})  # debe ignorarse en silencio


def test_unsubscribe():
    async def scenario():
        bus = EventBus()
        bus.bind_loop(asyncio.get_running_loop())
        q = bus.subscribe()
        bus.unsubscribe(q)
        assert q not in bus._subscribers

    _run(scenario())
