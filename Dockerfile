# Receta para construir la imagen del toolkit.
# Cada línea es un paso; Docker los ejecuta en orden y arma la "cajita".

# 1. De qué partimos: una imagen oficial de Python 3.12, versión "slim"
#    (liviana, sin cosas de más). Es la base sobre la que montamos todo.
FROM python:3.12-slim

# 2. Carpeta de trabajo adentro del contenedor. Lo que copiemos va acá.
WORKDIR /app

# 3. Copiamos PRIMERO solo las dependencias e instalamos.
#    Lo hacemos antes de copiar el código para aprovechar la cache de Docker:
#    si el código cambia pero las dependencias no, no reinstala todo de nuevo.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Ahora sí, copiamos el resto del código al contenedor.
COPY secutil.py .
COPY herramientas/ ./herramientas/

# 5. Qué se ejecuta al arrancar el contenedor: el comando secutil.
#    ENTRYPOINT fija el programa; lo que pases en 'docker run' van como
#    sus argumentos. Ej:  docker run toolkit-seguridad puertos scanme.nmap.org
ENTRYPOINT ["python3", "secutil.py"]
