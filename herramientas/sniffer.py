#!/usr/bin/env python3
"""
Sniffer de paquetes - v6 (argumentos por linea de comando)

Captura el trafico de TU red, lo analiza, lo guarda y grafica, y avisa de
trafico sin cifrar y posibles escaneos de puertos.

Ahora se configura al correr, sin editar el archivo:
    sudo python3 sniffer.py                       # 15 segundos, todo el trafico
    sudo python3 sniffer.py -s 30                  # 30 segundos
    sudo python3 sniffer.py -f tcp                 # solo TCP
    sudo python3 sniffer.py -s 60 -f "port 53"     # 60 seg, solo DNS
    sudo python3 sniffer.py --help                 # ver todas las opciones

USO ETICO: corré esto SOLO en tu propia red / tu propia maquina.
Capturar trafico de redes ajenas es ilegal.
"""

import os
import socket
import argparse
from collections import Counter, defaultdict
from datetime import datetime

# matplotlib es OPCIONAL: solo lo necesita el gráfico. Se importa dentro de
# hacer_grafico(), así el sniffer corre (captura, analiza, guarda pcap) aunque
# matplotlib no esté instalado. Mantiene liviana la imagen de Docker.
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP

socket.setdefaulttimeout(1)

SERVICIOS = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 3389: "RDP", 8080: "HTTP-alt",
}

INSEGUROS = {
    "HTTP": "usá HTTPS",
    "FTP": "usá SFTP/FTPS",
    "Telnet": "usá SSH",
    "POP3": "usá POP3S",
    "IMAP": "usá IMAPS",
    "SMTP": "usá SMTPS",
}

# --- Acumuladores ---
total = 0
por_protocolo = Counter()
ips_privadas = Counter()
ips_publicas = Counter()
servicios_usados = Counter()
conexiones = set()
sin_cifrar = Counter()
puertos_por_par = defaultdict(set)


def parsear_args(argv=None):
    """Define y lee las opciones de la linea de comando."""
    p = argparse.ArgumentParser(
        prog="secutil.py sniffer",
        description="Sniffer de paquetes educativo: captura, analiza y vigila tu red."
    )
    p.add_argument("-s", "--segundos", type=int, default=15,
                   help="cuantos segundos capturar (default: 15)")
    p.add_argument("-i", "--interfaz", default=None,
                   help="placa de red, ej: wlan0 (default: la del sistema)")
    p.add_argument("-f", "--filtro", default=None,
                   help="filtro BPF, ej: 'tcp', 'port 53', 'not port 443'")
    p.add_argument("--escaneo", type=int, default=15,
                   help="puertos distintos entre dos IPs para alertar escaneo (default: 15)")
    return p.parse_args(argv)


def es_privada(ip):
    if ip.startswith("192.168.") or ip.startswith("10."):
        return True
    if ip.startswith("172."):
        return 16 <= int(ip.split(".")[1]) <= 31
    return False


def puerto_de_servicio(sport, dport):
    for p in (sport, dport):
        if p in SERVICIOS:
            return p
    for p in (sport, dport):
        if p < 1024:
            return p
    return None


def nombre_protocolo(paquete):
    if paquete.haslayer(TCP):
        return "TCP"
    if paquete.haslayer(UDP):
        return "UDP"
    if paquete.haslayer(ICMP):
        return "ICMP"
    return "OTRO"


def procesar(paquete):
    global total
    if not paquete.haslayer(IP):
        return

    total += 1
    por_protocolo[nombre_protocolo(paquete)] += 1

    origen, destino = paquete[IP].src, paquete[IP].dst
    for ip in (origen, destino):
        if es_privada(ip):
            ips_privadas[ip] += 1
        else:
            ips_publicas[ip] += 1

    sport = dport = None
    if paquete.haslayer(TCP):
        sport, dport = paquete[TCP].sport, paquete[TCP].dport
    elif paquete.haslayer(UDP):
        sport, dport = paquete[UDP].sport, paquete[UDP].dport

    if sport is None:
        return

    puertos_por_par[(origen, destino)].add(dport)

    servicio = puerto_de_servicio(sport, dport)
    if servicio is None:
        return

    servicios_usados[servicio] += 1
    conexiones.add(frozenset({(origen, sport), (destino, dport)}))

    server_ip = destino if servicio == dport else origen
    nombre = SERVICIOS.get(servicio)
    if nombre in INSEGUROS:
        sin_cifrar[(server_ip, nombre)] += 1


def resolver(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def top_publicas_resueltas(n=5):
    return [(ip, resolver(ip), cuenta) for ip, cuenta in ips_publicas.most_common(n)]


def detectar_escaneos(umbral):
    sospechosos = []
    for (origen, destino), puertos in puertos_por_par.items():
        if len(puertos) >= umbral:
            sospechosos.append((origen, destino, len(puertos)))
    sospechosos.sort(key=lambda x: x[2], reverse=True)
    return sospechosos


def devolver_al_usuario(path):
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid:
        os.chown(path, int(uid), int(gid))


def guardar_pcap(paquetes):
    nombre = datetime.now().strftime("captura_%Y%m%d_%H%M%S.pcap")
    wrpcap(nombre, paquetes)
    devolver_al_usuario(nombre)
    return nombre


def acortar(texto, largo=22):
    return texto if len(texto) <= largo else texto[:largo - 1] + "…"


def hacer_grafico(top_pub):
    if total == 0:
        return None
    # Import perezoso de matplotlib: si no está instalado, se saltea el gráfico
    # (el resto del análisis y el pcap ya se hicieron igual).
    try:
        os.environ.setdefault("MPLCONFIGDIR", "/tmp/mpl")
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n(Grafico omitido: matplotlib no esta instalado. "
              "Instalalo con 'pip install matplotlib' si lo queres.)")
        return None
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    ax1.pie(list(por_protocolo.values()), labels=list(por_protocolo.keys()),
            autopct="%1.0f%%", startangle=90)
    ax1.set_title("Paquetes por protocolo")
    ax2.barh([acortar(n) for _, n, _ in top_pub], [c for _, _, c in top_pub])
    ax2.invert_yaxis()
    ax2.set_title("Top servers (paquetes)")
    ax2.set_xlabel("paquetes")
    plt.tight_layout()
    nombre = datetime.now().strftime("grafico_%Y%m%d_%H%M%S.png")
    plt.savefig(nombre, dpi=100)
    plt.close(fig)
    devolver_al_usuario(nombre)
    return nombre


def imprimir_resumen(top_pub, archivo_pcap, segundos, umbral_escaneo):
    print("\n" + "=" * 40)
    print(f"RESUMEN ({segundos} s)")
    print("=" * 40)
    print(f"\nPaquetes capturados: {total}")

    if total == 0:
        print("\nNo se capturo nada. Generá trafico mientras corre.")
        return

    print("\nPor protocolo:")
    for proto, cuenta in por_protocolo.most_common():
        print(f"  {proto:5} {cuenta}")

    print("\nDispositivos de tu red:")
    for ip, cuenta in ips_privadas.most_common(5):
        print(f"  {ip:16} {cuenta}")

    print("\nServers de internet:")
    for ip, nombre, cuenta in top_pub:
        print(f"  {ip:16} {cuenta:5}  {nombre}")

    print("\nServicios mas usados:")
    for puerto, cuenta in servicios_usados.most_common(5):
        print(f"  {puerto:5} {SERVICIOS.get(puerto, '?'):9} {cuenta}")

    print(f"\nConexiones distintas: {len(conexiones)}")

    if sin_cifrar:
        print("\n[!] Trafico SIN CIFRAR detectado:")
        for (ip, servicio), cuenta in sin_cifrar.most_common():
            print(f"    {servicio:7} con {ip}  ({cuenta} paq)  ->  {INSEGUROS[servicio]}")

    escaneos = detectar_escaneos(umbral_escaneo)
    if escaneos:
        print("\n[!] Posibles ESCANEOS de puertos:")
        for origen, destino, cuantos in escaneos:
            print(f"    {origen}  ->  {destino}  tocó {cuantos} puertos distintos")

    if not sin_cifrar and not escaneos:
        print("\n[ok] Sin trafico sin cifrar ni escaneos en esta captura.")

    print(f"\nGuardado: {archivo_pcap}  (abrilo con: wireshark {archivo_pcap})")


def main(argv=None):
    args = parsear_args(argv)

    print(f"Capturando {args.segundos} segundos... (Ctrl+C para cortar antes)\n")
    print("Generá trafico: abrí una web o tirá 'ping google.com' en otra terminal.\n")

    paquetes = sniff(iface=args.interfaz, filter=args.filtro, prn=procesar,
                     timeout=args.segundos, store=True)

    archivo_pcap = guardar_pcap(paquetes)
    top_pub = top_publicas_resueltas()
    imprimir_resumen(top_pub, archivo_pcap, args.segundos, args.escaneo)

    archivo_png = hacer_grafico(top_pub)
    if archivo_png:
        print(f"Grafico:  {archivo_png}  (abrilo con: xdg-open {archivo_png})")


if __name__ == "__main__":
    main()
