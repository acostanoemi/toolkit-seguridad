"""
Tests del analizador de logs.

La función analizar() es pura: le damos líneas de un log de autenticación y
nos devuelve los conteos. Le pasamos un log de mentira, con casos conocidos,
y chequeamos que cuente bien los fallos, las IPs y los logins exitosos.
"""
from herramientas import logs

# Log de ejemplo: 3 fallos de la misma IP (fuerza bruta), 1 de otra, 1 login OK
LOG = [
    "Oct 23 17:08:01 host sshd[1]: Failed password for root from 10.0.0.9 port 2 ssh2",
    "Oct 23 17:08:03 host sshd[1]: Failed password for root from 10.0.0.9 port 2 ssh2",
    "Oct 23 17:08:05 host sshd[1]: Failed password for invalid user admin from 10.0.0.9 port 2 ssh2",
    "Oct 23 18:00:00 host sshd[1]: Failed password for pepe from 200.1.2.3 port 2 ssh2",
    "Oct 23 18:05:00 host sshd[1]: Accepted password for soledad from 192.168.0.5 port 2 ssh2",
    "Oct 23 18:05:00 host CRON[9]: algo que no es un login y hay que ignorar",
]


def test_cuenta_los_fallos_totales():
    r = logs.analizar(LOG)
    assert r["total_fallos"] == 4


def test_agrupa_fallos_por_ip():
    r = logs.analizar(LOG)
    assert r["fallos_por_ip"]["10.0.0.9"] == 3
    assert r["fallos_por_ip"]["200.1.2.3"] == 1


def test_detecta_el_login_exitoso():
    r = logs.analizar(LOG)
    assert r["exitos"] == [("soledad", "192.168.0.5")]


def test_log_limpio_no_marca_nada():
    r = logs.analizar(["una linea cualquiera", "otra sin logins"])
    assert r["total_fallos"] == 0
    assert r["exitos"] == []
