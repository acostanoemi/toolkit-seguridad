#!/usr/bin/env python3
"""
Port scanner - v4 (banner grabbing + barra de progreso)

Le pasás una IP o un nombre y escanea un rango de puertos, en paralelo (hilos).
Por cada puerto abierto intenta leer el "banner": la linea de presentacion que
muchos servicios mandan al conectarse, que suele revelar el programa y version
(ej: "OpenSSH 8.9"). Y muestra una barra de progreso para rangos grandes.

Como funciona el scan: por cada puerto intenta abrir una conexion TCP. Si
conecta, hay un servicio escuchando -> abierto. Es trafico comun, NO necesita sudo.

Por que el banner importa: saber la version exacta de un servicio es el paso
previo a buscarle vulnerabilidades conocidas. Por eso muchos servidores la
ocultan a proposito. Leer banners es reconocimiento (recon).

USO ETICO Y LEGAL: escaneá SOLO tus propias maquinas o con permiso explicito.
Escanear equipos ajenos es la antesala de un ataque y es ilegal (Argentina,
ley 26.388). Blancos para practicar con permiso:
    127.0.0.1         -> tu propia maquina
    192.168.0.1       -> tu router
    scanme.nmap.org   -> server que Nmap ofrece justo para practicar

Uso:
    python3 port_scanner.py                          # 127.0.0.1, puertos 1-1024
    python3 port_scanner.py 192.168.0.1              # tu router
    python3 port_scanner.py scanme.nmap.org --hasta 65535
    python3 port_scanner.py 192.168.0.1 --desde 1 --hasta 100 --hilos 200
"""

import sys
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor

SERVICIOS = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-alt", 9929: "Nping-echo", 31337: "Elite/backdoor",
}


def parsear_args(argv=None):
    p = argparse.ArgumentParser(
        prog="secutil.py puertos",
        description="Escaner de puertos con hilos y banner grabbing."
    )
    p.add_argument("host", nargs="?", default="127.0.0.1",
                   help="IP o nombre a escanear (default: 127.0.0.1)")
    p.add_argument("--desde", type=int, default=1,
                   help="primer puerto del rango (default: 1)")
    p.add_argument("--hasta", type=int, default=1024,
                   help="ultimo puerto del rango (default: 1024)")
    p.add_argument("--hilos", type=int, default=100,
                   help="cuantos puertos probar en paralelo (default: 100)")
    p.add_argument("-t", "--timeout", type=float, default=0.5,
                   help="segundos a esperar por puerto (default: 0.5)")
    p.add_argument("--sin-banner", action="store_true",
                   help="no intentar leer el banner de los puertos abiertos")
    return p.parse_args(argv)


def leer_banner(ip, puerto, timeout):
    """
    Si el puerto esta abierto, intenta leer su banner (linea de presentacion).
    Para servicios web (80, 8080) manda un pedido HTTP minimo para provocar
    respuesta. Devuelve el banner limpio, o "" si no hubo.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, puerto))
            # Los servicios web no hablan primero: hay que pedirles algo.
            if puerto in (80, 8080, 8000, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            datos = s.recv(1024)
        # Nos quedamos con la primera linea, limpia de espacios y caracteres raros
        texto = datos.decode("utf-8", "ignore").strip()
        return texto.splitlines()[0] if texto else ""
    except Exception:
        return ""


def escanear(ip, puerto, timeout, con_banner):
    """Devuelve (puerto, abierto, banner). Banner solo si abierto y con_banner."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    abierto = s.connect_ex((ip, puerto)) == 0
    s.close()
    banner = ""
    if abierto and con_banner:
        banner = leer_banner(ip, puerto, timeout)
    return puerto, abierto, banner


def barra_progreso(hechos, total, ancho=30):
    """Dibuja una barra de progreso en la misma linea (se va sobrescribiendo)."""
    proporcion = hechos / total
    llenos = int(ancho * proporcion)
    barra = "#" * llenos + "-" * (ancho - llenos)
    # \r vuelve al principio de la linea; end="" evita el salto -> se sobrescribe
    print(f"\r  [{barra}] {hechos}/{total}", end="", flush=True)


def main(argv=None):
    args = parsear_args(argv)

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"No pude resolver '{args.host}'. Revisá el nombre o la conexion.")
        return

    cantidad = args.hasta - args.desde + 1
    con_banner = not args.sin_banner
    print(f"Escaneando {args.host} ({ip})")
    print(f"Puertos {args.desde}-{args.hasta} ({cantidad}), {args.hilos} hilos, "
          f"timeout {args.timeout}s, banner: {'si' if con_banner else 'no'}\n")

    puertos = range(args.desde, args.hasta + 1)
    abiertos = []
    hechos = 0

    def tarea(p):
        return escanear(ip, p, args.timeout, con_banner)

    with ThreadPoolExecutor(max_workers=args.hilos) as ejecutor:
        for puerto, esta_abierto, banner in ejecutor.map(tarea, puertos):
            hechos += 1
            barra_progreso(hechos, cantidad)
            if esta_abierto:
                abiertos.append((puerto, banner))

    print("\n")   # cerrar la linea de la barra
    if abiertos:
        for puerto, banner in sorted(abiertos):
            servicio = SERVICIOS.get(puerto, "?")
            linea = f"  [ABIERTO] {puerto:6}  {servicio}"
            if banner:
                linea += f"   ->  {banner}"
            print(linea)
        print(f"\n{len(abiertos)} puerto(s) abierto(s) en el rango {args.desde}-{args.hasta}.")
    else:
        print(f"Ningun puerto abierto en el rango {args.desde}-{args.hasta}.")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
