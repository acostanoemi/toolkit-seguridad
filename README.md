![tests](https://github.com/acostanoemi/toolkit-seguridad/actions/workflows/tests.yml/badge.svg)

# toolkit-seguridad

Conjunto de herramientas de seguridad de línea de comandos, escritas en Python,
bajo un solo comando: `secutil`. Funciona como `git` o `docker` — un comando
principal y varios subcomandos, cada uno una utilidad independiente.

Nació de consolidar siete scripts que antes vivían en repos separados. Juntarlos
bajo una CLI común los vuelve una herramienta de verdad, con tests y CI, en vez
de scripts sueltos.

## Herramientas

| Comando | Qué hace |
|---|---|
| `puertos` | Escanea puertos abiertos de un host, en paralelo, y lee el banner de cada servicio (recon). |
| `sniffer` | Captura el tráfico de tu red, lo resume y grafica, y avisa de tráfico sin cifrar o posibles escaneos. Requiere `sudo`. |
| `logs` | Analiza un log de autenticación (`auth.log`) y detecta fuerza bruta: IPs que insisten, usuarios apuntados, picos por hora. |
| `web` | Chequea una URL: HTTPS, redirección, headers de seguridad (HSTS, CSP, X-Frame-Options), cookies y SEO. |
| `integridad` | FIM casero: guarda una línea base por hash y después detecta archivos cambiados, borrados o nuevos. |
| `pwned` | Dice si una contraseña aparece en filtraciones, consultando HaveIBeenPwned con k-anonymity (nunca manda tu contraseña). |
| `cifrar` | Cifra y descifra archivos con una contraseña (Scrypt + Fernet). |

## Uso

```bash
python3 secutil.py                      # lista los comandos
python3 secutil.py <comando> --help     # ayuda de un comando

python3 secutil.py puertos 192.168.0.1
sudo python3 secutil.py sniffer -s 30 -f tcp
python3 secutil.py logs /var/log/auth.log --umbral 10
python3 secutil.py web https://ejemplo.com
python3 secutil.py integridad init ~/documentos
python3 secutil.py integridad check ~/documentos
python3 secutil.py pwned
python3 secutil.py cifrar cifrar documento.pdf
python3 secutil.py cifrar descifrar documento.pdf.cifrado
```

Cada herramienta se carga sólo cuando la usás (import perezoso): correr `pwned`
no necesita tener `scapy` ni `matplotlib` instalados.

## Instalación

```bash
git clone https://github.com/acostanoemi/toolkit-seguridad
cd toolkit-seguridad
pip install -r requirements.txt   # o instalá solo lo de la herramienta que uses
```

Qué necesita cada una:

- `cifrar` → `cryptography`
- `sniffer` → `scapy`, `matplotlib`
- `puertos`, `logs`, `web`, `integridad`, `pwned` → sólo la librería estándar

## Tests

```bash
pytest -v
```

El CI (GitHub Actions) corre todos los tests en un entorno limpio ante cada push.

## Uso ético y legal

Estas herramientas son para usar **sobre tus propios equipos, redes y sitios, o
con permiso explícito**. Escanear puertos, capturar tráfico o sondear sitios
ajenos es la antesala de un ataque y está penado en Argentina (ley 26.388).

## Estructura

```
secutil.py              el comando que reparte a cada herramienta
herramientas/           una herramienta por módulo
  puertos.py  sniffer.py  logs.py  web.py
  integridad.py  pwned.py  cifrar.py
tests/                  tests automáticos
```
