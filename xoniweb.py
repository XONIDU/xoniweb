#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XONI-WEB 2026 - Analizador de URLs (sin API Key)
Usa scraping publico de la interfaz web de VirusTotal via Selenium.
Desarrollado por: Darian Alberto Camacho Salas & Oscar Rodolfo Barragan Perez
#Somos XONINDU

Version robusta: el parser ya NO depende de que VirusTotal muestre un
resumen tipo "malicious: N" en texto plano (ese formato casi nunca aparece
en el HTML renderizado). En su lugar, recorre la lista de motores de
seguridad (Kaspersky, ESET, Google Safe Browsing, etc.) y su veredicto
individual (Clean, Malicious, Phishing, Suspicious, Unrated...), tal como
se ve en la pagina real, y clasifica cada uno.

Regla de deteccion: si la cantidad de motores con veredicto "malicioso"
o "sospechoso" es MAYOR A 0, el sitio se marca como infectado/riesgoso y
se reporta el TIPO de amenaza (malware, phishing, trojan, etc.) segun lo
que cada motor haya devuelto.
"""

import requests
from bs4 import BeautifulSoup
from datetime import datetime
import time
import re
import os
import urllib.parse
import sys
from collections import Counter

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

# Intentar importar Selenium
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("Selenium no disponible. Instala: pip install selenium webdriver-manager")

REPORTLAB_AVAILABLE = True  # ya importado arriba de forma obligatoria

# --------------------------------------------------------------------------
# Utilidades de consola
# --------------------------------------------------------------------------

def color(text):
    print("\033[1;31m" + text + "\033[0m")


def info(text):
    print("\033[1;36m" + text + "\033[0m")


def ok(text):
    print("\033[1;32m" + text + "\033[0m")


def warn(text):
    print("\033[1;33m" + text + "\033[0m")


# --------------------------------------------------------------------------
# WebDriver
# --------------------------------------------------------------------------

def get_webdriver():
    """Configura y retorna un driver de Chrome headless, probando varias rutas."""
    if not SELENIUM_AVAILABLE:
        return None

    options = Options()
    options.add_argument('--headless=new')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    options.add_argument('--window-size=1920,1080')
    options.add_argument('--disable-blink-features=AutomationControlled')
    options.add_argument(
        '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    )
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option('useAutomationExtension', False)

    intentos = [
        lambda: webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options),
        lambda: webdriver.Chrome(service=Service('/usr/bin/chromedriver'), options=options),
        lambda: webdriver.Chrome(options=options),
    ]

    for intento in intentos:
        try:
            driver = intento()
            driver.set_page_load_timeout(30)
            return driver
        except Exception:
            continue

    warn("No fue posible iniciar ningun WebDriver de Chrome/Chromium.")
    return None


# --------------------------------------------------------------------------
# Parser robusto de veredictos de VirusTotal
# --------------------------------------------------------------------------

# Palabras clave por categoria. El orden importa: se evalua de arriba a abajo.
CATEGORIAS_AMENAZA = [
    ("phishing", ["phishing"]),
    ("malware", ["malware", "trojan", "spyware", "ransomware", "worm", "backdoor"]),
    ("suspicious", ["suspicious"]),
    ("spam", ["spam"]),
    ("malicious_generico", ["malicious"]),
]

VEREDICTOS_LIMPIOS = {"clean", "harmless", "safe"}
VEREDICTOS_SIN_DATO = {"unrated", "timeout", "type-unsupported", "failure", "n/a", "-"}

# Todos los veredictos individuales que reconocemos como "linea de veredicto"
# (segun lo que realmente entrega la interfaz de VirusTotal)
VEREDICTOS_CONOCIDOS = (
    VEREDICTOS_LIMPIOS
    | VEREDICTOS_SIN_DATO
    | {"malicious", "malware", "trojan", "spyware", "ransomware", "worm",
       "backdoor", "suspicious", "spam", "phishing"}
)


def clasificar_veredicto(veredicto_texto):
    """Devuelve (categoria, es_amenaza:bool) para un veredicto individual."""
    v = veredicto_texto.strip().lower()

    if v in VEREDICTOS_LIMPIOS:
        return "clean", False
    if v in VEREDICTOS_SIN_DATO:
        return "unrated", False

    for categoria, palabras in CATEGORIAS_AMENAZA:
        if any(p in v for p in palabras):
            return categoria, True

    # Si no coincide con nada conocido, no lo contamos como amenaza
    return "otro", False


def extraer_veredictos_por_motor(texto_pagina):
    """
    Recorre el texto plano de la pagina y empareja cada motor de seguridad
    con su veredicto. Tolera DOS formatos que VirusTotal puede entregar
    segun como se extraiga el texto:

      Formato A (dos lineas):
          NombreDelMotor
          Veredicto

      Formato B (una linea, separados por espacio):
          NombreDelMotor Veredicto      (ej. "Fortinet Malware")

    Devuelve un dict {motor: veredicto_original}.
    """
    lineas = [l.strip() for l in texto_pagina.split("\n") if l.strip()]
    resultados = {}

    # Palabras que SOLO aparecen en oraciones de resumen generadas por VT
    # (ej. "No security vendors flagged this URL as: malicious",
    # "1 security vendor flagged this URL as: malware"), nunca en un nombre
    # real de motor de seguridad. Si alguna aparece como palabra suelta en
    # el candidato a "vendor", se descarta.
    PALABRAS_PROHIBIDAS = {
        "security", "vendor", "vendors", "flagged", "engines", "engine",
        "detected", "detect", "this", "url", "out", "no", "the", "as",
        "an", "have", "has", "did", "not", "none",
    }

    def es_vendor_valido(nombre):
        n = nombre.strip().rstrip(":").strip()
        if not n or len(n) > 60:
            return False
        if n.lower() in VEREDICTOS_CONOCIDOS:
            return False
        if n.lower().startswith(("security vendors", "community", "detection", "unread notifications")):
            return False

        palabras = re.findall(r"[a-zA-Z]+", n.lower())
        if len(palabras) > 5:
            return False  # los nombres reales de motores son cortos (1-4 palabras)
        if any(p in PALABRAS_PROHIBIDAS for p in palabras):
            return False
        if re.match(r"^\d+\s*/\s*\d+$", n):
            return False  # ej. "1/92"

        return True

    for i, linea in enumerate(lineas):
        linea_low = linea.lower()

        # --- Formato A: la linea ES un veredicto puro ---
        if linea_low in VEREDICTOS_CONOCIDOS:
            if i > 0:
                motor = lineas[i - 1]
                if es_vendor_valido(motor) and motor not in resultados:
                    resultados[motor] = linea
            continue

        # --- Formato B: "Vendor Veredicto" en la misma linea ---
        tokens = linea.split()
        if len(tokens) >= 2:
            ultimo = tokens[-1].strip(".,;:").lower()
            if ultimo in VEREDICTOS_CONOCIDOS:
                motor = " ".join(tokens[:-1])
                if es_vendor_valido(motor) and motor not in resultados:
                    resultados[motor] = tokens[-1]

    return resultados


def extraer_community_score(texto_pagina):
    """
    Busca el patron 'N / M' cercano a 'Community Score' que aparece en la
    pagina (ej. '1 / 92'). Devuelve (detectados, total) o (None, None).
    """
    idx = texto_pagina.lower().find("community score")
    ventana = texto_pagina[idx: idx + 300] if idx != -1 else texto_pagina[:300]
    match = re.search(r"(\d+)\s*/\s*(\d+)", ventana)
    if match:
        return int(match.group(1)), int(match.group(2))
    return None, None


def extraer_status_http(texto_pagina):
    match = re.search(r"Status\s*\n?\s*(\d{3})", texto_pagina)
    return match.group(1) if match else None


def analizar_texto_virustotal(texto_pagina):
    """
    Analiza el texto completo extraido de la pagina de VirusTotal y devuelve
    un dict con el resumen robusto del analisis.
    """
    veredictos = extraer_veredictos_por_motor(texto_pagina)
    detectados, total = extraer_community_score(texto_pagina)
    status_http = extraer_status_http(texto_pagina)

    por_categoria = {}
    motores_amenaza = []  # [(motor, veredicto, categoria)]

    for motor, veredicto in veredictos.items():
        categoria, es_amenaza = clasificar_veredicto(veredicto)
        por_categoria.setdefault(categoria, 0)
        por_categoria[categoria] += 1
        if es_amenaza:
            motores_amenaza.append((motor, veredicto, categoria))

    total_amenazas = len(motores_amenaza)
    tipos_detectados = Counter(cat for _, _, cat in motores_amenaza)

    return {
        "veredictos_por_motor": veredictos,
        "total_motores_analizados": len(veredictos),
        "por_categoria": por_categoria,
        "motores_amenaza": motores_amenaza,
        "total_amenazas": total_amenazas,
        "tipos_detectados": tipos_detectados,
        "community_score": (detectados, total),
        "status_http": status_http,
        "infectado": total_amenazas > 0,  # >0, tal como se pidio
    }


def formatear_reporte(url, resumen):
    """Convierte el dict de analisis en texto legible para TXT/consola/PDF."""
    lineas = []
    lineas.append(f"Resultados para {url}:")

    detectados, total = resumen["community_score"]
    if total:
        lineas.append(f"  - Community Score: {detectados} / {total}")

    if resumen["status_http"]:
        lineas.append(f"  - Status HTTP: {resumen['status_http']}")

    lineas.append(f"  - Motores analizados (con veredicto legible): {resumen['total_motores_analizados']}")
    for categoria, cantidad in sorted(resumen["por_categoria"].items()):
        lineas.append(f"      * {categoria}: {cantidad}")

    lineas.append("")
    if resumen["infectado"]:
        lineas.append(f"ADVERTENCIA! Se detectaron {resumen['total_amenazas']} motor(es) que marcan la URL como riesgosa.")
        lineas.append("Tipo(s) de amenaza detectada(s):")
        for tipo, cantidad in resumen["tipos_detectados"].most_common():
            lineas.append(f"  - {tipo}: {cantidad} motor(es)")
        lineas.append("")
        lineas.append("Detalle por motor:")
        for motor, veredicto, categoria in resumen["motores_amenaza"]:
            lineas.append(f"  - {motor}: {veredicto} ({categoria})")
    else:
        if resumen["total_motores_analizados"] == 0:
            lineas.append("No se pudieron leer veredictos de motores en la pagina (posible cambio de estructura o bloqueo).")
        else:
            lineas.append("La pagina esta limpia: 0 motores marcaron amenaza.")

    return "\n".join(lineas) + "\n"


# JS que recorre el DOM incluyendo shadow roots anidados y devuelve el texto
# visible aplanado. Esto es necesario porque VirusTotal renderiza la lista
# de motores dentro de Web Components (shadow DOM), que NO aparece en
# driver.page_source ni en BeautifulSoup por mas que se espere.
JS_EXTRAER_TEXTO_SHADOW = """
function collect(root) {
    let text = '';
    const nodes = root.childNodes ? Array.from(root.childNodes) : [];
    for (const n of nodes) {
        if (n.nodeType === Node.TEXT_NODE) {
            const t = n.textContent.trim();
            if (t) text += t + '\\n';
        } else if (n.nodeType === Node.ELEMENT_NODE) {
            if (n.tagName === 'SCRIPT' || n.tagName === 'STYLE') continue;
            if (n.shadowRoot) {
                text += collect(n.shadowRoot);
            }
            text += collect(n);
        }
    }
    return text;
}
return collect(document.body);
"""


def extraer_texto_renderizado(driver):
    """Obtiene el texto visible de la pagina, incluyendo contenido dentro de
    shadow DOM. Si falla, cae de regreso a BeautifulSoup sobre page_source."""
    try:
        texto = driver.execute_script(JS_EXTRAER_TEXTO_SHADOW)
        if texto and len(texto.strip()) > 50:
            return texto
    except Exception as e:
        warn("No se pudo extraer texto via shadow DOM (" + str(e) + "), usando fallback.")

    soup = BeautifulSoup(driver.page_source, "html.parser")
    return soup.get_text("\n")

def verificar_virus_selenium(url, archivo_txt=None, elementos_pdf=None, intentos=2):
    """Verifica una URL contra la GUI publica de VirusTotal usando Selenium."""
    info("Analizando con Selenium: " + url)

    styles = getSampleStyleSheet()
    search_url = "https://www.virustotal.com/gui/search?query=" + urllib.parse.quote(url, safe="")

    for intento_actual in range(1, intentos + 1):
        driver = None
        try:
            driver = get_webdriver()
            if not driver:
                mensaje = "No se pudo iniciar el navegador. Verifica las dependencias (Chrome/Chromedriver).\n"
                warn(mensaje)
                _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)
                return

            driver.get(search_url)

            # Espera activa a que cargue contenido real, atravesando shadow DOM
            # (VirusTotal renderiza los motores dentro de Web Components).
            try:
                WebDriverWait(driver, 20).until(
                    lambda d: len((d.execute_script(JS_EXTRAER_TEXTO_SHADOW) or "").strip()) > 300
                )
            except TimeoutException:
                if intento_actual < intentos:
                    warn(f"Timeout esperando contenido (intento {intento_actual}/{intentos}). Reintentando...")
                    driver.quit()
                    time.sleep(3)
                    continue
                mensaje = "Tiempo de espera agotado para VirusTotal tras varios intentos.\n"
                warn(mensaje)
                _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)
                return

            # Espera adicional: la lista de motores suele tardar un poco mas
            # en pintarse que el resto de la pagina (carga asincrona).
            time.sleep(4)

            texto_pagina = extraer_texto_renderizado(driver)
            resumen = analizar_texto_virustotal(texto_pagina)

            # Si aun asi no se leyo ningun motor, dale una segunda oportunidad
            # a esta misma carga antes de rendirte con este intento completo.
            if resumen["total_motores_analizados"] == 0:
                time.sleep(5)
                texto_pagina = extraer_texto_renderizado(driver)
                resumen = analizar_texto_virustotal(texto_pagina)

            mensaje = formatear_reporte(url, resumen)
            print(mensaje)
            _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)

            if resumen["total_motores_analizados"] == 0:
                _guardar_debug_html(driver.page_source, texto_pagina)
                if intento_actual < intentos:
                    warn(f"0 motores leidos (intento {intento_actual}/{intentos}). Reintentando con navegador nuevo...")
                    driver.quit()
                    time.sleep(3)
                    continue

            return  # exito (o agotamos intentos), no reintentar mas

        except WebDriverException as e:
            if intento_actual < intentos:
                warn(f"Error de WebDriver (intento {intento_actual}/{intentos}): {e}. Reintentando...")
                time.sleep(3)
                continue
            mensaje = "Error al verificar en VirusTotal (WebDriver): " + str(e) + "\n"
            warn(mensaje)
            _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)
            return
        except Exception as e:
            mensaje = "Error inesperado al verificar en VirusTotal: " + str(e) + "\n"
            warn(mensaje)
            _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)
            return
        finally:
            if driver:
                driver.quit()


def _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles):
    if archivo_txt:
        archivo_txt.write(mensaje + "\n")
    if elementos_pdf is not None:
        for line in mensaje.split("\n"):
            if line.strip():
                elementos_pdf.append(Paragraph(line, styles["Normal"]))
                elementos_pdf.append(Spacer(1, 4))


def _guardar_debug_html(html, texto_extraido=None):
    debug_dir = "debug_vt"
    os.makedirs(debug_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    debug_file = os.path.join(debug_dir, f"vt_{timestamp}.html")
    with open(debug_file, "w", encoding="utf-8") as f:
        f.write(html)
    info("HTML guardado para depuracion en: " + debug_file)

    if texto_extraido is not None:
        debug_txt = os.path.join(debug_dir, f"vt_{timestamp}_texto.txt")
        with open(debug_txt, "w", encoding="utf-8") as f:
            f.write(texto_extraido)
        info("Texto extraido (shadow DOM) guardado en: " + debug_txt)


# --------------------------------------------------------------------------
# Extraccion de enlaces
# --------------------------------------------------------------------------

def obtener_links(url, permitir_ssl_inseguro=True):
    """
    Obtiene todos los enlaces de una pagina web.

    Si falla la verificacion SSL (certificado local roto, CA faltante en el
    sistema, o sitio con certificado invalido), se reintenta una vez sin
    verificar el certificado -SOLO para poder listar los enlaces-, dejando
    muy claro en el reporte que esa conexion no fue validada. El analisis
    de virus contra VirusTotal no se ve afectado por esto.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        info("URL corregida a: " + url)

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    try:
        respuesta = requests.get(url, headers=headers, timeout=10, verify=True)
        respuesta.raise_for_status()
    except requests.exceptions.SSLError as e:
        if not permitir_ssl_inseguro:
            return "Error de certificado SSL al acceder a la pagina: " + str(e)

        warn(
            "Aviso: fallo la verificacion del certificado SSL local "
            "(posible falta de CA en el sistema, no un problema del sitio). "
            "Reintentando SIN verificar el certificado, solo para listar enlaces..."
        )
        try:
            respuesta = requests.get(url, headers=headers, timeout=10, verify=False)
            respuesta.raise_for_status()
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except requests.RequestException as e2:
            return "Error al acceder a la pagina incluso sin verificar SSL: " + str(e2)
    except requests.RequestException as e:
        return "Error al acceder a la pagina: " + str(e)

    try:
        soup = BeautifulSoup(respuesta.text, "html.parser")
        enlaces = [(a.get_text(strip=True), a["href"]) for a in soup.find_all("a", href=True)]
        return enlaces
    except Exception as e:
        return "Error al parsear el HTML de la pagina: " + str(e)


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------

def construir_pdf(nombre_archivo, titulo, elementos_pdf):
    """Genera un PDF con los elementos ya construidos (Paragraph/Spacer)."""
    try:
        doc = SimpleDocTemplate(nombre_archivo, pagesize=letter)
        styles = getSampleStyleSheet()
        titulo_style = ParagraphStyle(
            "TituloStyle", parent=styles["Heading1"], fontSize=16,
            alignment=TA_CENTER, spaceAfter=20
        )
        cuerpo = [Paragraph(titulo, titulo_style), Spacer(1, 12)] + elementos_pdf
        doc.build(cuerpo)
        return True
    except Exception as e:
        warn("Error generando PDF: " + str(e))
        return False


# --------------------------------------------------------------------------
# Flujo de analisis
# --------------------------------------------------------------------------

def analizar(url, archivo_txt=None, elementos_pdf=None):
    """Analiza una URL: extrae enlaces y verifica virus."""
    links = obtener_links(url)
    if isinstance(links, str):
        print(links)
        _escribir_salidas(links, archivo_txt, elementos_pdf, getSampleStyleSheet())
        return

    styles = getSampleStyleSheet()

    if archivo_txt:
        archivo_txt.write("Enlaces encontrados\n" + "=" * 50 + "\n\n")
    if elementos_pdf is not None:
        elementos_pdf.append(Paragraph("Enlaces encontrados", styles["Heading2"]))
        elementos_pdf.append(Spacer(1, 6))

    for texto, link in links:
        if link.startswith("/"):
            link = url.rstrip("/") + link
        linea = f"Texto: {texto}\nEnlace: {link}\n"
        print(linea)
        if archivo_txt:
            archivo_txt.write(linea + "\n")
        if elementos_pdf is not None:
            elementos_pdf.append(Paragraph("Texto: " + texto, styles["Normal"]))
            elementos_pdf.append(Paragraph("Enlace: " + link, styles["Normal"]))
            elementos_pdf.append(Spacer(1, 6))

    if archivo_txt:
        archivo_txt.write("\nResultado del analisis de virus\n" + "=" * 50 + "\n\n")
    if elementos_pdf is not None:
        elementos_pdf.append(Spacer(1, 12))
        elementos_pdf.append(Paragraph("Resultado del analisis de virus", styles["Heading2"]))
        elementos_pdf.append(Spacer(1, 6))

    verificar_virus_selenium(url, archivo_txt, elementos_pdf)


def analizar_all(url, archivo_txt=None, elementos_pdf=None):
    """Analiza todos los enlaces de una URL."""
    links = obtener_links(url)
    if isinstance(links, str):
        print(links)
        _escribir_salidas(links, archivo_txt, elementos_pdf, getSampleStyleSheet())
        return

    styles = getSampleStyleSheet()

    if archivo_txt:
        archivo_txt.write("Analisis completo de enlaces\n" + "=" * 50 + "\n\n")
    if elementos_pdf is not None:
        elementos_pdf.append(Paragraph("Analisis completo de enlaces", styles["Heading2"]))
        elementos_pdf.append(Spacer(1, 6))

    for texto, link in links:
        if link.startswith("/"):
            link = url.rstrip("/") + link
        print("Analizando enlace: " + link)
        if archivo_txt:
            archivo_txt.write("Analizando enlace: " + link + "\n")
        if elementos_pdf is not None:
            elementos_pdf.append(Paragraph("Analizando enlace: " + link, styles["Normal"]))
            elementos_pdf.append(Spacer(1, 6))

        verificar_virus_selenium(link, archivo_txt, elementos_pdf)

        if archivo_txt:
            archivo_txt.write("\n" + "-" * 40 + "\n\n")
        if elementos_pdf is not None:
            elementos_pdf.append(Paragraph("-" * 40, styles["Normal"]))
            elementos_pdf.append(Spacer(1, 6))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    formato = "txt"
    if len(sys.argv) > 1:
        formato = sys.argv[1]
    elif "XONIWEB_FORMATO" in os.environ:
        formato = os.environ["XONIWEB_FORMATO"]

    while True:
        color("""
 ╔════════════════════════════════════════════════════════╗
 ║                    XONI-WEB 2026                       ║
 ║              Analisis de URLs sin API Key              ║
 ║          Web Scraping + VirusTotal Publico (robusto)   ║
 ║                                                          ║
 ║         Desarrollado por: XONINDU - FES UNAM            ║
 ╚════════════════════════════════════════════════════════╝
        """)

        nombre_reporte = input("Nombre del Reporte (sin extension): ").strip()
        if not nombre_reporte:
            print("Nombre de reporte invalido.")
            continue

        url = input("Pagina web a analizar: ").strip()
        if not url:
            print("URL invalida.")
            continue

        opcion = input("""
Opciones:
  [0] Analizar solo la URL principal
  [1] Analizar todos los enlaces encontrados
Opcion: """).strip()

        generar_txt = formato in ("txt", "ambos")
        generar_pdf_flag = formato in ("pdf", "ambos")

        archivo_txt = None
        elementos_pdf = [] if generar_pdf_flag else None
        nombre_txt = nombre_reporte + ".txt"
        nombre_pdf = nombre_reporte + ".pdf"

        if generar_txt:
            archivo_txt = open(nombre_txt, "w", encoding="utf-8")
            archivo_txt.write("Reporte de analisis para: " + url + "\n" + "=" * 60 + "\n\n")

        ahora = datetime.now()
        fecha, hora = ahora.strftime("%Y-%m-%d"), ahora.strftime("%H:%M:%S")
        print(f"\nFecha: {fecha}\nHora: {hora}")

        if archivo_txt:
            archivo_txt.write(f"Fecha: {fecha}\nHora: {hora}\n\n" + "=" * 60 + "\n\n")
        if elementos_pdf is not None:
            styles = getSampleStyleSheet()
            elementos_pdf.append(Paragraph("Fecha: " + fecha, styles["Normal"]))
            elementos_pdf.append(Paragraph("Hora: " + hora, styles["Normal"]))
            elementos_pdf.append(Spacer(1, 12))

        if opcion == "0":
            analizar(url, archivo_txt, elementos_pdf)
        elif opcion == "1":
            analizar_all(url, archivo_txt, elementos_pdf)
        else:
            print("Opcion invalida.\n")
            if archivo_txt:
                archivo_txt.write("Opcion invalida.\n")
            if elementos_pdf is not None:
                elementos_pdf.append(Paragraph("Opcion invalida.", getSampleStyleSheet()["Normal"]))

        if archivo_txt:
            archivo_txt.close()
            ok("\nReporte TXT guardado en: " + nombre_txt)

        if elementos_pdf is not None:
            titulo = "XONI-WEB - Reporte de Analisis"
            if construir_pdf(nombre_pdf, titulo, elementos_pdf):
                ok("Reporte PDF guardado en: " + nombre_pdf)
            else:
                warn("Error generando PDF")

        print("\n" + "=" * 60)
        print("Resumen de archivos generados:")
        if generar_txt:
            print("  - " + nombre_txt)
        if generar_pdf_flag:
            print("  - " + nombre_pdf)
        print("=" * 60 + "\n")

        continuar = input("Analizar otra URL? (s/n): ").strip().lower()
        if continuar != "s":
            print("\nHasta luego! - #Somos XONINDU")
            break


if __name__ == "__main__":
    main()