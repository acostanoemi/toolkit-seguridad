#!/usr/bin/env python3
"""
Cifrador de archivos - v1

Cifra y descifra cualquier archivo con una contraseña. El archivo cifrado es
ilegible sin la clave. Mismo motor criptografico que un gestor de contraseñas
serio: Scrypt (derivar la clave) + Fernet (cifrar con verificacion de integridad).

Como funciona:
  - De tu contraseña se deriva una clave con Scrypt (lento a proposito: encarece
    el fuerza bruta), usando una "sal" aleatoria.
  - Con esa clave se cifra el archivo con Fernet.
  - El archivo .cifrado guarda: la sal + los datos cifrados. Sin la contraseña,
    es ilegible.

IMPORTANTE: si olvidás la contraseña, el archivo se perdió. No hay recuperacion:
esa es la prueba de que esta bien cifrado. Anotá la clave en un lugar seguro.

Requisitos: python3 y la libreria 'cryptography'
    sudo apt install python3-cryptography

Uso:
    python3 cifrar.py cifrar  documento.pdf                 # -> documento.pdf.cifrado
    python3 cifrar.py descifrar documento.pdf.cifrado       # -> documento.pdf
    python3 cifrar.py cifrar  foto.jpg -o secreto.bin       # nombre de salida propio
    python3 cifrar.py cifrar  datos.txt --borrar-original   # borra el original al terminar
"""

import os
import sys
import base64
import getpass
import argparse

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

LARGO_SAL = 16
EXT = ".cifrado"


def derivar_clave(password, sal):
    """De la contraseña + la sal, deriva la clave de cifrado con Scrypt."""
    kdf = Scrypt(salt=sal, length=32, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def pedir_password(confirmar=False):
    p = getpass.getpass("Contraseña: ")
    if not p:
        print("La contraseña no puede estar vacía.")
        sys.exit(1)
    if confirmar:
        if p != getpass.getpass("Repetir contraseña: "):
            print("No coinciden.")
            sys.exit(1)
    return p


def cmd_cifrar(args):
    if not os.path.isfile(args.archivo):
        print(f"No existe el archivo: {args.archivo}")
        return
    salida = args.salida or (args.archivo + EXT)
    if os.path.exists(salida) and input(f"'{salida}' ya existe. ¿Sobrescribir? (si/no): ").strip().lower() != "si":
        print("Cancelado.")
        return

    print("Elegí una contraseña. OJO: si la olvidás, el archivo se pierde.")
    password = pedir_password(confirmar=True)

    with open(args.archivo, "rb") as f:
        datos = f.read()

    sal = os.urandom(LARGO_SAL)
    fernet = Fernet(derivar_clave(password, sal))
    cifrado = fernet.encrypt(datos)

    with open(salida, "wb") as f:
        f.write(sal + cifrado)
    os.chmod(salida, 0o600)

    print(f"Cifrado: {salida}  ({len(datos)} bytes -> {os.path.getsize(salida)} bytes)")

    if args.borrar_original:
        os.remove(args.archivo)
        print(f"Original borrado: {args.archivo}")
        print("(Nota: un borrado comun no destruye los datos del disco por completo.)")


def cmd_descifrar(args):
    if not os.path.isfile(args.archivo):
        print(f"No existe el archivo: {args.archivo}")
        return

    # Nombre de salida: quitamos .cifrado si lo tiene
    if args.salida:
        salida = args.salida
    elif args.archivo.endswith(EXT):
        salida = args.archivo[:-len(EXT)]
    else:
        salida = args.archivo + ".descifrado"

    if os.path.exists(salida) and input(f"'{salida}' ya existe. ¿Sobrescribir? (si/no): ").strip().lower() != "si":
        print("Cancelado.")
        return

    password = pedir_password()

    with open(args.archivo, "rb") as f:
        contenido = f.read()
    sal, cifrado = contenido[:LARGO_SAL], contenido[LARGO_SAL:]

    fernet = Fernet(derivar_clave(password, sal))
    try:
        datos = fernet.decrypt(cifrado)
    except InvalidToken:
        print("Contraseña incorrecta o archivo dañado. No se pudo descifrar.")
        return

    with open(salida, "wb") as f:
        f.write(datos)
    print(f"Descifrado: {salida}  ({os.path.getsize(salida)} bytes)")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="secutil.py cifrar",description="Cifra y descifra archivos con una contraseña.")
    sub = p.add_subparsers(dest="comando", required=True)

    pc = sub.add_parser("cifrar", help="cifrar un archivo")
    pc.add_argument("archivo")
    pc.add_argument("-o", "--salida", help="nombre del archivo cifrado")
    pc.add_argument("--borrar-original", action="store_true", help="borrar el archivo original al terminar")

    pd = sub.add_parser("descifrar", help="descifrar un archivo")
    pd.add_argument("archivo")
    pd.add_argument("-o", "--salida", help="nombre del archivo descifrado")

    args = p.parse_args(argv)
    {"cifrar": cmd_cifrar, "descifrar": cmd_descifrar}[args.comando](args)


if __name__ == "__main__":
    main()
