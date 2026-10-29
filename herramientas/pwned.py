#!/usr/bin/env python3
"""
Chequeador de contraseñas filtradas - v2

Te dice si una contraseña (o varias, desde un archivo) aparece en filtraciones
conocidas, usando la API publica y gratuita de HaveIBeenPwned.

LO IMPORTANTE: nunca manda tu contraseña a ningun lado. Usa "k-anonymity":
  1. Calcula el hash SHA-1 de tu contraseña.
  2. Manda al servidor SOLO los primeros 5 caracteres del hash.
  3. El servidor devuelve TODOS los hashes filtrados que empiezan con esos 5.
  4. Busca tu hash completo en esa lista, aca en tu maquina.
El servidor nunca ve tu contraseña, ni su hash completo, ni cual te interesa.

Uso:
    python3 chequear_pass.py                      # una, te la pide oculta
    python3 chequear_pass.py --texto              # una, visible
    python3 chequear_pass.py --archivo claves.txt # varias, una por linea
"""

import sys
import time
import hashlib
import getpass
import argparse
import urllib.request

API = "https://api.pwnedpasswords.com/range/"


def veces_filtrada(password):
    """Devuelve cuantas veces aparece la password en filtraciones (0 = nunca)."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefijo, sufijo = sha1[:5], sha1[5:]
    with urllib.request.urlopen(API + prefijo, timeout=10) as r:
        cuerpo = r.read().decode()
    for linea in cuerpo.splitlines():
        suf, cuenta = linea.split(":")
        if suf == sufijo:
            return int(cuenta)
    return 0


def chequear_una(password):
    """Chequea una password e imprime el resultado. Devuelve True si esta filtrada."""
    try:
        veces = veces_filtrada(password)
    except Exception as e:
        print(f"  No pude consultar: {e}")
        return False
    if veces == 0:
        print("  [OK] no aparece en filtraciones conocidas.")
        return False
    print(f"  [!] FILTRADA: aparece {veces:,} veces. Cambiala.")
    return True


def chequear_archivo(ruta):
    """Chequea todas las contraseñas de un archivo (una por linea)."""
    try:
        with open(ruta, encoding="utf-8") as f:
            lineas = [l.rstrip("\n") for l in f if l.strip()]
    except FileNotFoundError:
        print(f"No existe el archivo: {ruta}")
        return

    print(f"Chequeando {len(lineas)} contraseña(s) de {ruta}\n")
    filtradas = 0
    for i, password in enumerate(lineas, 1):
        # Mostramos solo las primeras letras, nunca la contraseña entera
        pista = password[:2] + "***"
        print(f"{i}. {pista}")
        if chequear_una(password):
            filtradas += 1
        # Pausita para no golpear la API (es gratis, seamos prolijos)
        time.sleep(0.3)

    print(f"\nResumen: {filtradas} de {len(lineas)} están filtradas.")
    if filtradas:
        print("Cambiá las filtradas (generá nuevas con el gestor de contraseñas).")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="secutil.py pwned",
        description="Chequea si contraseñas aparecen en filtraciones conocidas."
    )
    p.add_argument("--texto", action="store_true",
                   help="escribir la contraseña visible (por defecto va oculta)")
    p.add_argument("--archivo", help="chequear varias desde un archivo (una por linea)")
    args = p.parse_args(argv)

    if args.archivo:
        chequear_archivo(args.archivo)
        return

    if args.texto:
        password = input("Contraseña a chequear: ")
    else:
        password = getpass.getpass("Contraseña a chequear (no se ve): ")

    if not password:
        print("No escribiste nada.")
        return

    print()
    chequear_una(password)


if __name__ == "__main__":
    main()
