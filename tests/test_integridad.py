"""
Tests del verificador de integridad (FIM).

Usamos tmp_path (carpeta temporal de pytest) para crear archivos de prueba y
chequear que el hash sea determinista, que escanear() los encuentre a todos, y
que un cambio en el contenido cambie el hash (que es justo lo que detecta un FIM).
"""
from herramientas import integridad


def test_hash_es_determinista(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"contenido")
    assert integridad.hash_archivo(f) == integridad.hash_archivo(f)


def test_hash_cambia_si_cambia_el_contenido(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"antes")
    h1 = integridad.hash_archivo(f)
    f.write_bytes(b"despues")
    h2 = integridad.hash_archivo(f)
    assert h1 != h2


def test_escanear_encuentra_todos_los_archivos(tmp_path):
    (tmp_path / "uno.txt").write_bytes(b"1")
    (tmp_path / "dos.txt").write_bytes(b"2")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "tres.txt").write_bytes(b"3")

    hashes = integridad.escanear(tmp_path)
    assert len(hashes) == 3  # incluye el de la subcarpeta (rglob es recursivo)
