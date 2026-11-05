"""Tests de integridad del dataset demo y del blindaje de fw."""
import os
import subprocess

from core import demo
from core import fw


def test_hosts_con_ip_unica_y_mac_valida():
    ips = [h["ip"] for h in demo.HOSTS]
    assert len(ips) == len(set(ips))
    for h in demo.HOSTS:
        assert len(h["mac"].split(":")) == 6
        assert h["os"]


def test_todos_los_hosts_de_discovery_tienen_datos_en_el_dataset():
    flat = {h["ip"] for h in demo.hosts()}
    detailed = {h["ip"] for h in demo.HOSTS}
    assert flat == detailed


def test_topologia_nodos_y_aristas_coherentes():
    ids = {n["id"] for n in demo.TOPOLOGY["nodes"]}
    for edge in demo.TOPOLOGY["edges"]:
        assert edge["source"] in ids
        assert edge["target"] in ids


def test_puertos_demo_validos():
    for h in demo.HOSTS:
        for p in h["ports"]:
            assert 0 < p["port"] < 65535


def test_is_demo_respeta_variable_de_entorno():
    old = os.environ.get(demo.DEMO_ENV)
    try:
        os.environ[demo.DEMO_ENV] = "1"
        assert demo.is_demo()
        os.environ[demo.DEMO_ENV] = "0"
        assert not demo.is_demo()
        del os.environ[demo.DEMO_ENV]
        assert not demo.is_demo()
    finally:
        if old is not None:
            os.environ[demo.DEMO_ENV] = old


def test_fw_run_con_binario_inexistente_no_lanza_excepcion():
    proc = fw._run("binario-que-no-existe-12345", ["-S"])
    assert proc.returncode != 0


def test_fw_peek_es_seguro_sin_iptables(monkeypatch):
    # En Windows/macOS no hay iptables: peek debe devolver 0 sin reventar.
    assert fw.peek() == 0
