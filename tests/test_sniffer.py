"""
Tests del sniffer de paquetes.

Probamos las dos funciones puras (las que no dependen de capturar red):
  - es_privada: decide si una IP es de tu red local o de internet.
  - puerto_de_servicio: de los dos puertos de un paquete, cuál es el del servicio.

pytest.mark.parametrize corre el mismo test con varios casos de una, así no
repetimos código.
"""
import pytest
from herramientas import sniffer


@pytest.mark.parametrize("ip, esperado", [
    ("192.168.0.1", True),    # red hogareña típica
    ("10.0.0.5", True),       # otra red privada
    ("172.16.0.1", True),     # rango privado 172.16–172.31
    ("172.31.255.1", True),
    ("172.32.0.1", False),    # fuera del rango privado
    ("8.8.8.8", False),       # internet (DNS de Google)
    ("45.33.32.156", False),  # internet
])
def test_es_privada(ip, esperado):
    assert sniffer.es_privada(ip) == esperado


@pytest.mark.parametrize("sport, dport, esperado", [
    (59820, 443, 443),    # vos -> servidor HTTPS
    (443, 59820, 443),    # servidor HTTPS -> vos (la respuesta)
    (40000, 53, 53),      # consulta DNS
    (9431, 9431, None),   # broadcast raro: ninguno es servicio
    (57018, 38052, None), # dos puertos efímeros: ningún servicio
])
def test_puerto_de_servicio(sport, dport, esperado):
    assert sniffer.puerto_de_servicio(sport, dport) == esperado
