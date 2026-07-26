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
import random
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

# undetected-chromedriver: parchea el binario de Chromedriver para que no
# se detecten las huellas tipicas de automatizacion (navigator.webdriver,
# CDP runtime flags, etc). Es opcional pero MUY recomendado para VirusTotal,
# que activamente detecta bots. Instala con: pip install undetected-chromedriver
try:
    import undetected_chromedriver as uc
    UNDETECTED_AVAILABLE = True
except ImportError:
    UNDETECTED_AVAILABLE = False

REPORTLAB_AVAILABLE = True  # ya importado arriba de forma obligatoria

# User-Agents realistas para rotar (reduce la huella de "siempre el mismo bot")
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

# JS que se inyecta en CADA pagina nueva (antes de que corra el JS del sitio)
# para esconder las huellas mas comunes de Selenium/Headless Chrome.
JS_STEALTH = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['es-MX', 'es', 'en-US', 'en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
window.chrome = { runtime: {} };
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission })
        : originalQuery(parameters)
);
"""

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
    """
    Configura y retorna un driver de Chrome headless, priorizando
    undetected-chromedriver (evade la deteccion de bots de VirusTotal)
    y cayendo de regreso a Selenium normal con parches manuales si no
    esta disponible.
    """
    if not SELENIUM_AVAILABLE:
        return None

    user_agent = random.choice(USER_AGENTS)

    # --- Opcion 1: undetected-chromedriver (recomendado) ---
    if UNDETECTED_AVAILABLE:
        try:
            uc_options = uc.ChromeOptions()
            uc_options.add_argument('--no-sandbox')
            uc_options.add_argument('--disable-dev-shm-usage')
            uc_options.add_argument('--window-size=1920,1080')
            uc_options.add_argument('--lang=es-MX')
            uc_options.add_argument('--user-agent=' + user_agent)
            # headless=new via undetected_chromedriver es mas detectable;
            # se deja en modo "headless clasico" que uc maneja internamente.
            driver = uc.Chrome(options=uc_options, headless=True, use_subprocess=True)
            driver.set_page_load_timeout(30)
            try:
                driver.execute_cdp_cmd(
                    "Page.addScriptToEvaluateOnNewDocument", {"source": JS_STEALTH}
                )
            except Exception:
                pass
            return driver
        except Exception as e:
            warn("undetected-chromedriver fallo (" + str(e) + "), usando Selenium normal...")

    # --- Opcion 2: Selenium normal con parches manuales ---
    options = Options()
    options.add_argument('--headless=new')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    options.add_argument('--window-size=1920,1080')
    options.add_argument('--lang=es-MX')
    options.add_argument('--disable-blink-features=AutomationControlled')
    options.add_argument('--user-agent=' + user_agent)
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
            try:
                driver.execute_cdp_cmd(
                    "Page.addScriptToEvaluateOnNewDocument", {"source": JS_STEALTH}
                )
            except Exception:
                pass
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


MARCADOR_LISTA_MOTORES = "security vendors' analysis"


def esperar_reporte_completo(driver, timeout=40):
    """
    Espera de forma inteligente a que VirusTotal termine de pintar la lista
    de motores, en vez de confiar en un simple conteo de caracteres (que
    se cumple con solo el menu/navbar y da lugar a lecturas de "0 motores"
    por pura carrera de tiempos).

    Estrategia:
      1. Sondea el texto renderizado cada ~1.5s.
      2. Considera "cargado" cuando aparece el marcador real de la seccion
         de motores Y el contenido deja de crecer entre dos sondeos
         seguidos (indica que ya no se estan pintando mas nodos).
      3. Si se agota el timeout sin ver el marcador, devuelve el ultimo
         texto que logro leer de todos modos (mejor esfuerzo).

    Devuelve (texto, encontrado_marcador: bool).
    """
    inicio = time.time()
    texto_anterior = ""
    veces_estable = 0

    while time.time() - inicio < timeout:
        texto_actual = extraer_texto_renderizado(driver)
        contiene_marcador = MARCADOR_LISTA_MOTORES in texto_actual.lower()

        if contiene_marcador:
            if texto_actual == texto_anterior:
                veces_estable += 1
                if veces_estable >= 2:
                    return texto_actual, True
            else:
                veces_estable = 0
            texto_anterior = texto_actual
        else:
            texto_anterior = texto_actual

        time.sleep(1.5)

    # Se agoto el tiempo: devolvemos lo ultimo que se pudo leer, marcando
    # si al menos el marcador llego a aparecer alguna vez.
    return texto_anterior, (MARCADOR_LISTA_MOTORES in texto_anterior.lower())


def _cerrar_driver_seguro(driver):
    if driver:
        try:
            driver.quit()
        except Exception:
            pass


def verificar_virus_selenium(url, archivo_txt=None, elementos_pdf=None, intentos=2, driver=None):
    """
    Verifica una URL contra la GUI publica de VirusTotal usando Selenium.

    Si se pasa 'driver', REUTILIZA esa misma sesion de navegador (mismas
    cookies, mismo fingerprint) en vez de lanzar un Chrome nuevo. Esto es
    clave para analizar varias URLs seguidas: lanzar un navegador nuevo por
    cada una parece "un visitante distinto" en cada peticion, que es
    exactamente el patron que dispara la deteccion de bot / rate-limit de
    VirusTotal. Una sola sesion navegando varias paginas de reporte se ve
    mucho mas humano.

    Devuelve (exito: bool, driver): el driver se devuelve para que el
    llamador lo siga reutilizando en la siguiente URL. Puede ser distinto
    al que se paso (si hubo que reiniciarlo por un error) o None (si no se
    pudo levantar ninguno).
    """
    info("Analizando con Selenium: " + url)

    styles = getSampleStyleSheet()
    search_url = "https://www.virustotal.com/gui/search?query=" + urllib.parse.quote(url, safe="")

    for intento_actual in range(1, intentos + 1):
        try:
            if driver is None:
                driver = get_webdriver()
                if not driver:
                    mensaje = "No se pudo iniciar el navegador. Verifica las dependencias (Chrome/Chromedriver).\n"
                    warn(mensaje)
                    _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)
                    return False, None

            # Pequeña pausa antes de navegar, como haria un humano al pegar
            # la URL y darle enter (peticiones instantaneas son sospechosas).
            time.sleep(random.uniform(0.8, 2.2))
            driver.get(search_url)

            # Espera adicional fija: dale tiempo a la app de VirusTotal a
            # arrancar (Angular/Web Components) antes de empezar a sondear.
            time.sleep(5)

            # Espera inteligente: sondea hasta ver el marcador real de la
            # seccion de motores Y que el contenido se estabilice, en vez
            # de confiar en un simple conteo de caracteres.
            texto_pagina, encontro_marcador = esperar_reporte_completo(driver, timeout=30)

            if not encontro_marcador:
                _guardar_debug_html(driver.page_source, texto_pagina)
                if intento_actual < intentos:
                    warn(f"No aparecio la lista de motores a tiempo (intento {intento_actual}/{intentos}). Reintentando con navegador nuevo...")
                    _cerrar_driver_seguro(driver)
                    driver = None
                    time.sleep(random.uniform(2.5, 5))
                    continue
                mensaje = "Tiempo de espera agotado: VirusTotal nunca mostro la lista de motores tras varios intentos.\n"
                warn(mensaje)
                _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)
                return False, driver

            resumen = analizar_texto_virustotal(texto_pagina)

            # Si el marcador aparecio pero aun asi no se leyo ningun motor
            # (caso raro: estructura distinta a la esperada), dale una
            # segunda oportunidad de lectura antes de rendirte.
            if resumen["total_motores_analizados"] == 0:
                time.sleep(random.uniform(4, 6.5))
                texto_pagina = extraer_texto_renderizado(driver)
                resumen = analizar_texto_virustotal(texto_pagina)

            mensaje = formatear_reporte(url, resumen)
            print(mensaje)
            _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)

            if resumen["total_motores_analizados"] == 0:
                _guardar_debug_html(driver.page_source, texto_pagina)
                if intento_actual < intentos:
                    warn(f"0 motores leidos (intento {intento_actual}/{intentos}). Reintentando con navegador nuevo...")
                    _cerrar_driver_seguro(driver)
                    driver = None
                    time.sleep(random.uniform(2.5, 5))
                    continue
                return False, driver

            return True, driver  # exito, driver se devuelve para reutilizar

        except WebDriverException as e:
            _cerrar_driver_seguro(driver)
            driver = None
            if intento_actual < intentos:
                warn(f"Error de WebDriver (intento {intento_actual}/{intentos}): {e}. Reintentando con navegador nuevo...")
                time.sleep(3)
                continue
            mensaje = "Error al verificar en VirusTotal (WebDriver): " + str(e) + "\n"
            warn(mensaje)
            _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)
            return False, None
        except Exception as e:
            mensaje = "Error inesperado al verificar en VirusTotal: " + str(e) + "\n"
            warn(mensaje)
            _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)
            return False, driver

    return False, driver


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


def es_link_analizable(link):
    """
    Descarta enlaces que no son URLs web reales y que solo desperdician
    peticiones contra VirusTotal (anclas, protocolos de apps, enlaces vacios).
    """
    if not link or link.strip() in ("#", ""):
        return False
    link_low = link.strip().lower()
    protocolos_no_analizables = (
        "javascript:", "mailto:", "tel:", "whatsapp:", "intent:",
        "fb-messenger:", "sms:", "data:",
    )
    if link_low.startswith(protocolos_no_analizables):
        return False
    if link_low.startswith("#"):
        return False
    return True


def normalizar_links(links, url_base, limite=None):
    """
    Convierte enlaces relativos a absolutos, descarta los no analizables
    y elimina duplicados preservando el orden. Si se pasa 'limite', corta
    la lista a esa cantidad.
    """
    vistos = set()
    resultado = []
    for texto, link in links:
        link_abs = link
        if link_abs.startswith("/"):
            link_abs = url_base.rstrip("/") + link_abs
        if not es_link_analizable(link_abs):
            continue
        if link_abs in vistos:
            continue
        vistos.add(link_abs)
        resultado.append((texto, link_abs))
        if limite and len(resultado) >= limite:
            break
    return resultado


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

    _exito, driver = verificar_virus_selenium(url, archivo_txt, elementos_pdf)
    _cerrar_driver_seguro(driver)


def _pausar_con_backoff(fallos_consecutivos):
    """
    Calcula y espera una pausa entre analisis. Si hay 2+ fallos consecutivos
    (0 motores leidos), asume posible bloqueo/rate-limit de VirusTotal y
    aplica un backoff exponencial (con jitter), avisando al usuario, en vez
    de la pausa corta normal.
    """
    UMBRAL_BACKOFF = 2
    TOPE_SEGUNDOS = 180

    if fallos_consecutivos < UMBRAL_BACKOFF:
        time.sleep(random.uniform(3, 7))
        return

    # Backoff exponencial: 2 fallos -> ~20-30s, 3 -> ~40-55s, 4 -> ~80-100s, tope 180s
    base = min(TOPE_SEGUNDOS, 10 * (2 ** (fallos_consecutivos - UMBRAL_BACKOFF + 1)))
    espera = base + random.uniform(0, base * 0.3)
    warn(
        f"Posible bloqueo/rate-limit de VirusTotal detectado "
        f"({fallos_consecutivos} fallos seguidos). Esperando {espera:.0f}s antes de continuar..."
    )
    time.sleep(espera)


def analizar_all(url, archivo_txt=None, elementos_pdf=None, limite=None):
    """Analiza los enlaces de una URL (filtrados y sin duplicados)."""
    links_crudos = obtener_links(url)
    if isinstance(links_crudos, str):
        print(links_crudos)
        _escribir_salidas(links_crudos, archivo_txt, elementos_pdf, getSampleStyleSheet())
        return

    links = normalizar_links(links_crudos, url, limite=limite)

    styles = getSampleStyleSheet()
    descartados = len(links_crudos) - len(links)

    info(f"Enlaces encontrados: {len(links_crudos)} | analizables: {len(links)} | descartados (# / javascript: / duplicados / etc.): {descartados}")

    if archivo_txt:
        archivo_txt.write("Analisis completo de enlaces\n" + "=" * 50 + "\n\n")
    if elementos_pdf is not None:
        elementos_pdf.append(Paragraph("Analisis completo de enlaces", styles["Heading2"]))
        elementos_pdf.append(Spacer(1, 6))

    fallos_consecutivos = 0
    driver_sesion = None
    for idx, (texto, link) in enumerate(links):
        print("Analizando enlace: " + link)
        if archivo_txt:
            archivo_txt.write("Analizando enlace: " + link + "\n")
        if elementos_pdf is not None:
            elementos_pdf.append(Paragraph("Analizando enlace: " + link, styles["Normal"]))
            elementos_pdf.append(Spacer(1, 6))

        exito, driver_sesion = verificar_virus_selenium(
            link, archivo_txt, elementos_pdf, driver=driver_sesion
        )
        fallos_consecutivos = 0 if exito else fallos_consecutivos + 1

        # Si se acumulan fallos, ademas del backoff, refresca la sesion
        # completa (nuevo navegador = nuevo fingerprint) por si el bloqueo
        # esta atado a esta sesion en particular.
        if fallos_consecutivos >= 2:
            _cerrar_driver_seguro(driver_sesion)
            driver_sesion = None

        if archivo_txt:
            archivo_txt.write("\n" + "-" * 40 + "\n\n")
        if elementos_pdf is not None:
            elementos_pdf.append(Paragraph("-" * 40, styles["Normal"]))
            elementos_pdf.append(Spacer(1, 6))

        # Pausa entre consultas: corta si todo va bien, con backoff
        # escalonado si se acumulan fallos (posible bloqueo/rate-limit).
        if idx < len(links) - 1:
            _pausar_con_backoff(fallos_consecutivos)

    _cerrar_driver_seguro(driver_sesion)


def analizar_lista_manual(urls, archivo_txt=None, elementos_pdf=None):
    """Analiza una lista de URLs dadas manualmente por el usuario (sin scraping previo)."""
    styles = getSampleStyleSheet()

    # Deduplicar preservando orden, y descartar vacios/no analizables
    vistas = set()
    urls_limpias = []
    for u in urls:
        u = u.strip()
        if not u or not es_link_analizable(u):
            continue
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        if u in vistas:
            continue
        vistas.add(u)
        urls_limpias.append(u)

    if archivo_txt:
        archivo_txt.write("Analisis de lista de enlaces proporcionada\n" + "=" * 50 + "\n\n")
    if elementos_pdf is not None:
        elementos_pdf.append(Paragraph("Analisis de lista de enlaces proporcionada", styles["Heading2"]))
        elementos_pdf.append(Spacer(1, 6))

    fallos_consecutivos = 0
    driver_sesion = None
    for idx, link in enumerate(urls_limpias):
        print("Analizando enlace: " + link)
        if archivo_txt:
            archivo_txt.write("Analizando enlace: " + link + "\n")
        if elementos_pdf is not None:
            elementos_pdf.append(Paragraph("Analizando enlace: " + link, styles["Normal"]))
            elementos_pdf.append(Spacer(1, 6))

        exito, driver_sesion = verificar_virus_selenium(
            link, archivo_txt, elementos_pdf, driver=driver_sesion
        )
        fallos_consecutivos = 0 if exito else fallos_consecutivos + 1

        if fallos_consecutivos >= 2:
            _cerrar_driver_seguro(driver_sesion)
            driver_sesion = None

        if archivo_txt:
            archivo_txt.write("\n" + "-" * 40 + "\n\n")
        if elementos_pdf is not None:
            elementos_pdf.append(Paragraph("-" * 40, styles["Normal"]))
            elementos_pdf.append(Spacer(1, 6))

        if idx < len(urls_limpias) - 1:
            _pausar_con_backoff(fallos_consecutivos)

    _cerrar_driver_seguro(driver_sesion)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def reiniciar_proceso():
    """
    Reinicia el programa por COMPLETO: reemplaza el proceso actual de Python
    por uno nuevo desde cero (os.execv), como si cerraras la terminal y
    volvieras a correr `python xoniweb.py` a mano.

    Esto es mas agresivo que solo cerrar el navegador (_cerrar_driver_seguro):
    limpia cualquier estado que pudiera haber quedado colgado (procesos
    zombie de Chrome, perfiles temporales de undetected-chromedriver,
    variables en memoria, etc.) que un simple driver.quit() no garantiza
    borrar del todo. Util cuando VirusTotal empieza a bloquear despues de
    la primera URL: se arranca "de fabrica" para la siguiente.

    Nota: al ser un proceso nuevo, se volvera a pedir el nombre de reporte
    y todo desde el inicio (no hay forma de continuar "en caliente" un
    reinicio real del proceso).
    """
    print()
    warn("Reiniciando el programa por completo (nuevo proceso), para no arrastrar nada de la sesion anterior...")
    time.sleep(random.uniform(1.5, 3))
    sys.stdout.flush()
    os.execv(sys.executable, [sys.executable] + sys.argv)


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

        opcion = input("""
Opciones:
  [0] Analizar solo una URL principal
  [1] Analizar una URL principal + los enlaces que encuentre en ella
  [2] Yo doy la lista de enlaces a analizar (tu decides cuantos)
Opcion: """).strip()

        if opcion not in ("0", "1", "2"):
            print("Opcion invalida.\n")
            continue

        url = None
        lista_manual = []
        limite_enlaces = None

        if opcion in ("0", "1"):
            url = input("Pagina web a analizar: ").strip()
            if not url:
                print("URL invalida.")
                continue
            if opcion == "1":
                limite_txt = input(
                    "Maximo de enlaces a analizar de esa pagina (Enter = sin limite): "
                ).strip()
                if limite_txt.isdigit() and int(limite_txt) > 0:
                    limite_enlaces = int(limite_txt)
        else:  # opcion == "2"
            cantidad_txt = input("Cuantos enlaces quieres analizar?: ").strip()
            if not cantidad_txt.isdigit() or int(cantidad_txt) <= 0:
                print("Cantidad invalida.")
                continue
            cantidad = int(cantidad_txt)
            for i in range(1, cantidad + 1):
                enlace = input(f"  Enlace {i}/{cantidad}: ").strip()
                if enlace:
                    lista_manual.append(enlace)
            if not lista_manual:
                print("No se ingreso ningun enlace valido.")
                continue

        generar_txt = formato in ("txt", "ambos")
        generar_pdf_flag = formato in ("pdf", "ambos")

        archivo_txt = None
        elementos_pdf = [] if generar_pdf_flag else None
        nombre_txt = nombre_reporte + ".txt"
        nombre_pdf = nombre_reporte + ".pdf"

        titulo_reporte = url if url else f"{len(lista_manual)} enlace(s) proporcionados manualmente"

        if generar_txt:
            archivo_txt = open(nombre_txt, "w", encoding="utf-8")
            archivo_txt.write("Reporte de analisis para: " + titulo_reporte + "\n" + "=" * 60 + "\n\n")

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
            analizar_all(url, archivo_txt, elementos_pdf, limite=limite_enlaces)
        elif opcion == "2":
            analizar_lista_manual(lista_manual, archivo_txt, elementos_pdf)

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

        reiniciar_proceso()


if __name__ == "__main__":
    main()