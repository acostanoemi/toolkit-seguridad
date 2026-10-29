#!/usr/bin/env python3
"""
Analizador de logs de seguridad - v1

Lee un log de autenticacion (tipo /var/log/auth.log) y detecta señales de
ataque: intentos de login fallidos, IPs que insisten (fuerza bruta) y a que
horas se concentran.

Para que sirve: los logs tienen miles de lineas y a ojo no ves nada. Este
script los resume y marca lo sospechoso. Es parte del trabajo diario de un
analista de seguridad (revisar logs en busca de intrusiones).

USO: analizá tus propios logs o de sistemas que administres.

Uso:
    python3 analizar_logs.py                      # lee /var/log/auth.log
    python3 analizar_logs.py /ruta/a/otro.log     # otro archivo
    python3 analizar_logs.py --umbral 10          # alerta IPs con 10+ fallos
"""

import re
import sys
import argparse
from collections import Counter, defaultdict

# Patrones tipicos de un intento de login FALLIDO en auth.log (SSH)
PATRONES_FALLO = [
    re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)"),
]
# Login EXITOSO (para contrastar)
PATRON_OK = re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")
# La hora suele estar al principio: "Oct 23 17:08:01 ..."
PATRON_HORA = re.compile(r"^\w{3}\s+\d+\s+(\d{2}):\d{2}:\d{2}")


def parsear_args(argv=None):
    p = argparse.ArgumentParser(
        prog="secutil.py logs",
        description="Analiza un log de autenticacion en busca de señales de ataque."
    )
    p.add_argument("archivo", nargs="?", default="/var/log/auth.log",
                   help="log a analizar (default: /var/log/auth.log)")
    p.add_argument("--umbral", type=int, default=5,
                   help="cuantos fallos de una IP para marcarla sospechosa (default: 5)")
    return p.parse_args(argv)


def analizar(lineas):
    fallos_por_ip = Counter()
    fallos_por_usuario = Counter()
    fallos_por_hora = Counter()
    exitos = []
    total_fallos = 0

    for linea in lineas:
        # Intentos fallidos
        for patron in PATRONES_FALLO:
            m = patron.search(linea)
            if m:
                usuario, ip = m.group(1), m.group(2)
                fallos_por_ip[ip] += 1
                fallos_por_usuario[usuario] += 1
                total_fallos += 1
                h = PATRON_HORA.match(linea)
                if h:
                    fallos_por_hora[h.group(1)] += 1
                break
        # Logins exitosos
        m = PATRON_OK.search(linea)
        if m:
            exitos.append((m.group(1), m.group(2)))

    return {
        "fallos_por_ip": fallos_por_ip,
        "fallos_por_usuario": fallos_por_usuario,
        "fallos_por_hora": fallos_por_hora,
        "exitos": exitos,
        "total_fallos": total_fallos,
    }


def main(argv=None):
    args = parsear_args(argv)

    try:
        with open(args.archivo, encoding="utf-8", errors="ignore") as f:
            lineas = f.readlines()
    except FileNotFoundError:
        print(f"No existe el archivo: {args.archivo}")
        return
    except PermissionError:
        print(f"Sin permiso para leer {args.archivo}. Probá con sudo, o pasá otro archivo.")
        return

    r = analizar(lineas)

    print(f"Analizando: {args.archivo}  ({len(lineas)} lineas)\n")
    print(f"Logins fallidos: {r['total_fallos']}")
    print(f"Logins exitosos: {len(r['exitos'])}")

    if r["total_fallos"] == 0:
        print("\nNo se encontraron intentos de login fallidos. Tranquilo.")
        return

    print("\nTop IPs con mas fallos (candidatas a fuerza bruta):")
    for ip, cuenta in r["fallos_por_ip"].most_common(10):
        alerta = "  <-- SOSPECHOSA" if cuenta >= args.umbral else ""
        print(f"  {ip:16} {cuenta} fallos{alerta}")

    print("\nUsuarios mas apuntados:")
    for usuario, cuenta in r["fallos_por_usuario"].most_common(5):
        print(f"  {usuario:16} {cuenta}")

    print("\nFallos por hora (para ver picos):")
    for hora in sorted(r["fallos_por_hora"]):
        barra = "#" * min(r["fallos_por_hora"][hora], 50)
        print(f"  {hora}:00  {barra} {r['fallos_por_hora'][hora]}")

    # Alerta final
    sospechosas = [ip for ip, c in r["fallos_por_ip"].items() if c >= args.umbral]
    print()
    if sospechosas:
        print(f"[!] {len(sospechosas)} IP(s) superan el umbral de {args.umbral} fallos: "
              f"{', '.join(sospechosas)}")
        print("    Podrían ser ataques de fuerza bruta. Considerá bloquearlas (fail2ban).")
    else:
        print(f"[ok] Ninguna IP supera el umbral de {args.umbral} fallos.")


if __name__ == "__main__":
    main()
