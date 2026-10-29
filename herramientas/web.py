#!/usr/bin/env python3
"""
Escaner de checklist web - v1

Le pasás una URL y verifica automaticamente varios puntos de seguridad y SEO:
HTTPS, headers de seguridad, robots.txt, sitemap, favicon, meta descripcion,
cookies seguras. Convierte una checklist manual en un chequeo automatico.

Pensado para revisar tus propios sitios (o con permiso). No hace ataques:
solo pide paginas y mira las respuestas, como un navegador.

Uso:
    python3 escanear_web.py https://ejemplo.com
    python3 escanear_web.py ejemplo.com          # le agrega https:// solo
"""

import sys
import ssl
import argparse
import urllib.request
import urllib.error
from urllib.parse import urlparse

TIMEOUT = 10
UA = {"User-Agent": "Mozilla/5.0 (chequeo-checklist-web)"}


def pedir(url, metodo="GET"):
    """Hace una peticion y devuelve (status, headers, cuerpo_texto)."""
    req = urllib.request.Request(url, headers=UA, method=metodo)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        cuerpo = r.read(100000).decode("utf-8", "ignore") if metodo == "GET" else ""
        return r.status, dict(r.headers), cuerpo, r.geturl()


def ok(texto):   print(f"  [OK]  {texto}")
def mal(texto):  print(f"  [!]   {texto}")
def info(texto): print(f"  [..]  {texto}")


def chequear(url):
    parsed = urlparse(url)
    dominio = f"{parsed.scheme}://{parsed.netloc}"

    print(f"Escaneando: {url}\n")

    # --- HTTPS ---
    print("HTTPS y transporte:")
    if parsed.scheme == "https":
        ok("La URL usa HTTPS")
    else:
        mal("La URL no usa HTTPS")
    # ¿http redirige a https?
    try:
        _, _, _, final = pedir("http://" + parsed.netloc)
        if final.startswith("https"):
            ok("http redirige a https")
        else:
            mal("http NO redirige a https (queda sin cifrar)")
    except Exception:
        info("No pude probar la redireccion http->https")

    # --- Pedido principal para ver headers y cuerpo ---
    try:
        status, headers, cuerpo, final = pedir(dominio)
    except Exception as e:
        mal(f"No pude acceder al sitio: {e}")
        return
    headers_low = {k.lower(): v for k, v in headers.items()}

    # --- Headers de seguridad ---
    print("\nHeaders de seguridad:")
    chequeos_headers = {
        "strict-transport-security": "HSTS (fuerza https en el navegador)",
        "content-security-policy": "Content-Security-Policy (contra XSS)",
        "x-frame-options": "X-Frame-Options (contra clickjacking)",
        "x-content-type-options": "X-Content-Type-Options (contra MIME sniffing)",
    }
    for header, desc in chequeos_headers.items():
        if header in headers_low:
            ok(desc)
        else:
            mal(f"Falta: {desc}")

    # --- Cookies seguras ---
    print("\nCookies:")
    set_cookie = headers_low.get("set-cookie", "")
    if not set_cookie:
        info("El sitio no manda cookies en la portada")
    else:
        if "secure" in set_cookie.lower():
            ok("Las cookies tienen flag Secure")
        else:
            mal("Cookies sin flag Secure (viajarian sin cifrar)")
        if "httponly" in set_cookie.lower():
            ok("Las cookies tienen flag HttpOnly")
        else:
            mal("Cookies sin HttpOnly (accesibles por JavaScript)")

    # --- SEO basico (en el HTML) ---
    print("\nSEO y metadatos:")
    cl = cuerpo.lower()
    if "<title>" in cl:
        ok("Tiene <title>")
    else:
        mal("Falta <title>")
    if 'name="description"' in cl or "name='description'" in cl:
        ok("Tiene meta description")
    else:
        mal("Falta meta description")
    if 'property="og:' in cl:
        ok("Tiene Open Graph (preview al compartir)")
    else:
        mal("Falta Open Graph (el link compartido se ve pobre)")

    # --- Archivos que deberian existir ---
    print("\nArchivos del sitio:")
    for ruta, nombre in [("/favicon.ico", "favicon"),
                         ("/robots.txt", "robots.txt"),
                         ("/sitemap.xml", "sitemap.xml")]:
        try:
            st, _, _, _ = pedir(dominio + ruta)
            if st == 200:
                ok(f"Existe {nombre}")
            else:
                mal(f"Falta {nombre} (status {st})")
        except Exception:
            mal(f"Falta {nombre}")

    print("\nNota: esto cubre lo automatizable. El contraste de colores, el CTA,")
    print("la validacion de formularios y la pagina 404 hay que revisarlos a ojo.")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="secutil.py web",description="Chequea puntos de seguridad y SEO de una web.")
    p.add_argument("url", help="URL a chequear (ej: https://ejemplo.com)")
    args = p.parse_args(argv)

    url = args.url
    if not url.startswith("http"):
        url = "https://" + url

    chequear(url)


if __name__ == "__main__":
    main()
