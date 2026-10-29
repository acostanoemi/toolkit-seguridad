#!/usr/bin/env python3
"""
secutil - Toolkit de seguridad

Una sola herramienta con varios comandos. Cada comando es una utilidad de
seguridad independiente: escanear puertos, sniffear la red, analizar logs,
chequear una web, vigilar archivos, buscar contraseñas filtradas y cifrar
archivos.

Funciona como git o docker: un comando principal (secutil) y subcomandos.

    python3 secutil.py                      # lista los comandos
    python3 secutil.py <comando> --help     # ayuda de un comando
    python3 secutil.py puertos 192.168.0.1  # ejemplo

USO ETICO Y LEGAL: usá estas herramientas SOLO sobre tus propios equipos,
redes y sitios, o con permiso explicito. En Argentina, el acceso no autorizado
a sistemas ajenos esta penado (ley 26.388).
"""
import sys
import importlib

# nombre del comando -> (modulo dentro de herramientas/, descripcion corta)
COMANDOS = {
    "puertos":    ("puertos",    "Escanea puertos abiertos de un host (con banner grabbing)"),
    "sniffer":    ("sniffer",    "Captura y analiza el trafico de tu red (requiere sudo)"),
    "logs":       ("logs",       "Analiza logs de login en busca de fuerza bruta"),
    "web":        ("web",        "Chequea HTTPS, headers de seguridad y SEO de una web"),
    "integridad": ("integridad", "Vigila archivos y detecta cambios/borrados (FIM)"),
    "pwned":      ("pwned",      "Chequea si una contraseña aparece en filtraciones"),
    "cifrar":     ("cifrar",     "Cifra y descifra archivos con una contraseña"),
}


def ayuda():
    print(__doc__.strip())
    print("\nComandos disponibles:\n")
    for nombre, (_, desc) in COMANDOS.items():
        print(f"  {nombre:11} {desc}")
    print("\nAyuda de un comando concreto:  python3 secutil.py <comando> --help")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv or argv[0] in ("-h", "--help", "help"):
        ayuda()
        return

    comando = argv[0]
    if comando not in COMANDOS:
        print(f"Comando desconocido: {comando}\n")
        ayuda()
        sys.exit(1)

    nombre_modulo = COMANDOS[comando][0]
    # Import perezoso: cargamos SOLO la herramienta pedida. Asi 'pwned' no
    # necesita scapy ni matplotlib instalados, por ejemplo.
    modulo = importlib.import_module(f"herramientas.{nombre_modulo}")
    # Le pasamos al comando sus propios argumentos (lo que viene despues del nombre)
    modulo.main(argv[1:])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCortado.")
    except BrokenPipeError:
        # Pasa al usar '| head' o '| less': el otro lado cierra la cañería
        # antes de que terminemos de escribir. No es un error real.
        try:
            sys.stdout.close()
        except Exception:
            pass
