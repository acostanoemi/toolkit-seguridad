#!/usr/bin/env python3
"""
Verificador de integridad de archivos (FIM casero) - v1

Vigila archivos importantes y avisa si alguno cambio, se borro o aparecio uno
nuevo, sin que vos lo tocaras. Util para detectar que un atacante o malware
modifico archivos del sistema.

Como funciona (usa HASH, igual que el buscador de duplicados, pero para
seguridad): guarda una "linea base" con el hash de cada archivo cuando confiás
en ellos. Despues compara: mismo hash = intacto; hash distinto = cambio;
falta = borrado; nuevo = apareció. El hash detecta cualquier cambio, hasta de
un solo byte.

Esto se llama FIM (File Integrity Monitoring), parte de los HIDS. Herramientas
pro como AIDE o Tripwire hacen esto mismo.

Uso:
    python3 verificar_integridad.py init ~/carpeta       # crear linea base
    python3 verificar_integridad.py check ~/carpeta      # chequear cambios
"""

import sys
import json
import hashlib
import argparse
from pathlib import Path

ARCHIVO_BASE = "integridad_base.json"   # donde se guarda la linea base


def hash_archivo(ruta, bloque=65536):
    """Hash SHA-256 del contenido de un archivo, leido de a bloques."""
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        while True:
            datos = f.read(bloque)
            if not datos:
                break
            h.update(datos)
    return h.hexdigest()


def escanear(carpeta):
    """Devuelve un dict {ruta: hash} de todos los archivos de la carpeta."""
    base = Path(carpeta).expanduser()
    hashes = {}
    for archivo in base.rglob("*"):
        if archivo.is_file():
            try:
                hashes[str(archivo)] = hash_archivo(archivo)
            except (PermissionError, OSError):
                continue
    return hashes


def cmd_init(args):
    carpeta = Path(args.carpeta).expanduser()
    if not carpeta.is_dir():
        print(f"No existe la carpeta: {carpeta}")
        return
    hashes = escanear(carpeta)
    base = {"carpeta": str(carpeta), "hashes": hashes}
    with open(ARCHIVO_BASE, "w", encoding="utf-8") as f:
        json.dump(base, f, indent=2)
    print(f"Linea base creada: {len(hashes)} archivo(s) registrados.")
    print(f"Guardada en {ARCHIVO_BASE}. Chequeá cambios con: check {args.carpeta}")


def cmd_check(args):
    try:
        with open(ARCHIVO_BASE, encoding="utf-8") as f:
            base = json.load(f)
    except FileNotFoundError:
        print(f"No hay linea base. Creala primero con: init {args.carpeta}")
        return

    viejos = base["hashes"]
    nuevos = escanear(Path(args.carpeta).expanduser())

    set_viejos, set_nuevos = set(viejos), set(nuevos)

    modificados = [r for r in set_viejos & set_nuevos if viejos[r] != nuevos[r]]
    borrados = sorted(set_viejos - set_nuevos)
    aparecidos = sorted(set_nuevos - set_viejos)
    intactos = len(set_viejos & set_nuevos) - len(modificados)

    print(f"Chequeando {args.carpeta} contra la linea base\n")
    print(f"Intactos:    {intactos}")
    print(f"Modificados: {len(modificados)}")
    print(f"Borrados:    {len(borrados)}")
    print(f"Nuevos:      {len(aparecidos)}")

    if modificados:
        print("\n[!] MODIFICADOS (cambiaron desde la linea base):")
        for r in sorted(modificados):
            print(f"    {r}")
    if borrados:
        print("\n[!] BORRADOS (estaban y ya no):")
        for r in borrados:
            print(f"    {r}")
    if aparecidos:
        print("\n[!] NUEVOS (aparecieron, no estaban en la base):")
        for r in aparecidos:
            print(f"    {r}")

    if not (modificados or borrados or aparecidos):
        print("\n[ok] Todo intacto. Ningun archivo cambio.")
    else:
        print("\nSi vos hiciste estos cambios, actualizá la base con: init "
              f"{args.carpeta}")
        print("Si NO los hiciste, revisá: alguien o algo pudo haber tocado tus archivos.")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="secutil.py integridad",
        description="Verificador de integridad de archivos (FIM): detecta cambios por hash."
    )
    sub = p.add_subparsers(dest="comando", required=True)

    pi = sub.add_parser("init", help="crear la linea base (foto de confianza)")
    pi.add_argument("carpeta", help="carpeta a vigilar")

    pc = sub.add_parser("check", help="chequear cambios contra la linea base")
    pc.add_argument("carpeta", help="carpeta a chequear")

    args = p.parse_args(argv)
    {"init": cmd_init, "check": cmd_check}[args.comando](args)


if __name__ == "__main__":
    main()
