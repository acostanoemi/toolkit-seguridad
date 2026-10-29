"""
Tests del cifrador de archivos.

'monkeypatch' es una herramienta de pytest para reemplazar algo temporalmente:
acá la usamos para que getpass (que normalmente pide la contraseña por teclado)
devuelva una clave fija, así el test corre solo, sin intervención.
'tmp_path' es una carpeta temporal que pytest crea y borra para cada test.
"""
import argparse
from herramientas import cifrar


def test_derivar_clave_es_determinista():
    sal = b"0123456789abcdef"
    assert cifrar.derivar_clave("clave", sal) == cifrar.derivar_clave("clave", sal)


def test_derivar_clave_cambia_con_la_password():
    sal = b"0123456789abcdef"
    assert cifrar.derivar_clave("clave", sal) != cifrar.derivar_clave("otra", sal)


def test_cifrar_y_descifrar_devuelve_lo_mismo(tmp_path, monkeypatch):
    monkeypatch.setattr(cifrar.getpass, "getpass", lambda *a, **k: "clave123")
    original = tmp_path / "doc.txt"
    original.write_bytes(b"contenido secreto 123")
    cif = tmp_path / "doc.cifrado"

    cifrar.cmd_cifrar(argparse.Namespace(archivo=str(original), salida=str(cif), borrar_original=False))
    assert cif.exists()
    # el archivo cifrado NO debe contener el texto legible
    assert b"contenido secreto" not in cif.read_bytes()

    salida = tmp_path / "recuperado.txt"
    cifrar.cmd_descifrar(argparse.Namespace(archivo=str(cif), salida=str(salida)))
    # al descifrar, vuelve idéntico al original
    assert salida.read_bytes() == b"contenido secreto 123"


def test_descifrar_con_clave_incorrecta_no_escribe(tmp_path, monkeypatch):
    monkeypatch.setattr(cifrar.getpass, "getpass", lambda *a, **k: "correcta")
    original = tmp_path / "d.txt"
    original.write_bytes(b"algo")
    cif = tmp_path / "d.cifrado"
    cifrar.cmd_cifrar(argparse.Namespace(archivo=str(original), salida=str(cif), borrar_original=False))

    # ahora intentamos descifrar con la clave equivocada
    monkeypatch.setattr(cifrar.getpass, "getpass", lambda *a, **k: "incorrecta")
    salida = tmp_path / "out.txt"
    cifrar.cmd_descifrar(argparse.Namespace(archivo=str(cif), salida=str(salida)))
    # como la clave es incorrecta, NO debe generar el archivo descifrado
    assert not salida.exists()
