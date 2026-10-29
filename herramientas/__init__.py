"""
Herramientas del toolkit de seguridad.

Cada módulo es una utilidad independiente con su propia función main(argv).
El dispatcher (secutil.py) las carga de a una, solo cuando se usan, así una
herramienta que no necesita scapy o cryptography no obliga a instalarlos.
"""
