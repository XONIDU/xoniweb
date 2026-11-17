# XONIWEB en Docker (Render)
# =============================
# Imagen con Python + Chromium para que Selenium funcione en el servidor.
# Sin Chromium, el analisis sigue funcionando con las fuentes sin APIs
# (OpenPhish, DNSBL, heuristica, fetch); con Chromium se suman el
# analisis de contenido de la pagina y VirusTotal (solo sus motores
# confiables) como fuentes mas.
#
# Render usa este Dockerfile cuando el servicio es de tipo Docker
# (ver render.yaml). El puerto lo asigna Render con la variable PORT.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Chromium + chromedriver del sistema (el codigo prefiere el chromedriver
# de /usr/bin antes que descargar uno con webdriver-manager).
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Directorios de trabajo (reportes, subidas y cache de listas).
RUN mkdir -p reportes uploads data

EXPOSE 5505

# waitress (servidor de produccion) en el puerto que asigne Render.
CMD ["sh", "-c", "waitress-serve --host=0.0.0.0 --port=${PORT:-5505} xoniweb_web:app"]
