"""Tests de utilidades puras: parseo de puertos y calculo de CIDR."""
from modules.portscan import COMMON_PORTS, parse_ports
from core.netutils import to_cidr


def test_parse_ports_none_devuelve_comunes():
    assert parse_ports(None) == COMMON_PORTS


def test_parse_ports_lista():
    assert parse_ports([22, 80, 443]) == [22, 80, 443]


def test_parse_ports_rango_y_sueltos():
    assert parse_ports("22,80,100-102,443") == [22, 80, 100, 101, 102, 443]


def test_parse_ports_rango_invertido():
    assert parse_ports("200-198") == [198, 199, 200]


def test_parse_ports_filtra_invalidos():
    assert parse_ports("0,70000,80") == [80]


def test_to_cidr_normal():
    assert to_cidr("192.168.1.10", "255.255.255.0") == "192.168.1.0/24"


def test_to_cidr_mascara_rara():
    assert to_cidr("10.0.0.5", "255.255.0.0") == "10.0.0.0/16"


def test_to_cidr_invalido_devuelve_none():
    assert to_cidr("no-ip", "255.255.255.0") is None
    assert to_cidr(None, None) is None
    assert to_cidr("10.0.0.5", None) is None
