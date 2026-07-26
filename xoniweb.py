#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XONI-WEB 2026 - Analizador de URLs (sin API Key)
Usa scraping publico de la interfaz web de VirusTotal via Selenium.
Desarrollado por: Darian Alberto Camacho Salas & Oscar Rodolfo Barragan Perez
#Somos XONINDU

Version robusta con REUTILIZACION DE SESION: el navegador se mantiene
abierto entre analisis de URLs, simulando el comportamiento de un humano
que navega varias paginas de reporte en la misma sesion. Esto reduce
drasticamente la deteccion de bot por parte de VirusTotal.

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
# se detecten las huellas tipicas de automatizacion
try:
    import undetected_chromedriver as uc
    UNDETECTED_AVAILABLE = True
except ImportError:
    UNDETECTED_AVAILABLE = False

REPORTLAB_AVAILABLE = True

# User-Agents realistas para rotar
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

# JS para ocultar huellas de automatizacion
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
# WebDriver - SESION PERSISTENTE
# --------------------------------------------------------------------------

class DriverManager:
    """Maneja una unica instancia del navegador reutilizable entre URLs."""
    
    _instance = None
    _driver = None
    
    @classmethod
    def get_driver(cls, force_new=False):
        """Obtiene el driver reutilizable. Si no existe, lo crea."""
        if force_new or cls._driver is None:
            cls._driver = cls._crear_driver()
        return cls._driver
    
    @classmethod
    def _crear_driver(cls):
        """Crea una nueva instancia del driver con configuracion stealth."""
        if not SELENIUM_AVAILABLE:
            return None
        
        user_agent = random.choice(USER_AGENTS)
        
        # --- Opcion 1: undetected-chromedriver ---
        if UNDETECTED_AVAILABLE:
            try:
                uc_options = uc.ChromeOptions()
                uc_options.add_argument('--no-sandbox')
                uc_options.add_argument('--disable-dev-shm-usage')
                uc_options.add_argument('--window-size=1920,1080')
                uc_options.add_argument('--lang=es-MX')
                uc_options.add_argument('--user-agent=' + user_agent)
                driver = uc.Chrome(options=uc_options, headless=True, use_subprocess=True)
                driver.set_page_load_timeout(30)
                try:
                    driver.execute_cdp_cmd(
                        "Page.addScriptToEvaluateOnNewDocument", {"source": JS_STEALTH}
                    )
                except Exception:
                    pass
                info("Driver creado con undetected-chromedriver (sesion persistente)")
                return driver
            except Exception as e:
                warn("undetected-chromedriver fallo (" + str(e) + "), usando Selenium normal...")
        
        # --- Opcion 2: Selenium normal ---
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
                info("Driver creado con Selenium normal (sesion persistente)")
                return driver
            except Exception:
                continue
        
        warn("No fue posible iniciar ningun WebDriver de Chrome/Chromium.")
        return None
    
    @classmethod
    def cerrar(cls):
        """Cierra el driver si existe."""
        if cls._driver:
            try:
                cls._driver.quit()
            except Exception:
                pass
            cls._driver = None
            info("Sesion del navegador cerrada")

# --------------------------------------------------------------------------
# Extraccion de enlaces
# --------------------------------------------------------------------------

def obtener_links(url, permitir_ssl_inseguro=True):
    """
    Obtiene todos los enlaces de una pagina web.
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
        warn("Aviso: fallo la verificacion del certificado SSL. Reintentando sin verificar...")
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
    """Descarta enlaces que no son URLs web reales."""
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
    """Convierte enlaces relativos a absolutos, descarta los no analizables y elimina duplicados."""
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
# Parser de VirusTotal
# --------------------------------------------------------------------------

CATEGORIAS_AMENAZA = [
    ("phishing", ["phishing"]),
    ("malware", ["malware", "trojan", "spyware", "ransomware", "worm", "backdoor"]),
    ("suspicious", ["suspicious"]),
    ("spam", ["spam"]),
    ("malicious_generico", ["malicious"]),
]

VEREDICTOS_LIMPIOS = {"clean", "harmless", "safe"}
VEREDICTOS_SIN_DATO = {"unrated", "timeout", "type-unsupported", "failure", "n/a", "-"}

VEREDICTOS_CONOCIDOS = (
    VEREDICTOS_LIMPIOS
    | VEREDICTOS_SIN_DATO
    | {"malicious", "malware", "trojan", "spyware", "ransomware", "worm",
       "backdoor", "suspicious", "spam", "phishing"}
)

def clasificar_veredicto(veredicto_texto):
    v = veredicto_texto.strip().lower()
    if v in VEREDICTOS_LIMPIOS:
        return "clean", False
    if v in VEREDICTOS_SIN_DATO:
        return "unrated", False
    for categoria, palabras in CATEGORIAS_AMENAZA:
        if any(p in v for p in palabras):
            return categoria, True
    return "otro", False

def extraer_veredictos_por_motor(texto_pagina):
    lineas = [l.strip() for l in texto_pagina.split("\n") if l.strip()]
    resultados = {}
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
            return False
        if any(p in PALABRAS_PROHIBIDAS for p in palabras):
            return False
        if re.match(r"^\d+\s*/\s*\d+$", n):
            return False
        return True

    for i, linea in enumerate(lineas):
        linea_low = linea.lower()
        if linea_low in VEREDICTOS_CONOCIDOS:
            if i > 0:
                motor = lineas[i - 1]
                if es_vendor_valido(motor) and motor not in resultados:
                    resultados[motor] = linea
            continue
        tokens = linea.split()
        if len(tokens) >= 2:
            ultimo = tokens[-1].strip(".,;:").lower()
            if ultimo in VEREDICTOS_CONOCIDOS:
                motor = " ".join(tokens[:-1])
                if es_vendor_valido(motor) and motor not in resultados:
                    resultados[motor] = tokens[-1]
    return resultados

def extraer_community_score(texto_pagina):
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
    veredictos = extraer_veredictos_por_motor(texto_pagina)
    detectados, total = extraer_community_score(texto_pagina)
    status_http = extraer_status_http(texto_pagina)
    por_categoria = {}
    motores_amenaza = []
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
        "infectado": total_amenazas > 0,
    }

def formatear_reporte(url, resumen):
    lineas = []
    lineas.append(f"Resultados para {url}:")
    detectados, total = resumen["community_score"]
    if total:
        lineas.append(f"  - Community Score: {detectados} / {total}")
    if resumen["status_http"]:
        lineas.append(f"  - Status HTTP: {resumen['status_http']}")
    lineas.append(f"  - Motores analizados: {resumen['total_motores_analizados']}")
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
            lineas.append("No se pudieron leer veredictos de motores en la pagina.")
        else:
            lineas.append("La pagina esta limpia: 0 motores marcaron amenaza.")
    return "\n".join(lineas) + "\n"

# JS para extraer texto del Shadow DOM
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
    return texto_anterior, (MARCADOR_LISTA_MOTORES in texto_anterior.lower())

def verificar_virus_selenium(url, archivo_txt=None, elementos_pdf=None, intentos=3):
    info("Analizando con Selenium: " + url)
    styles = getSampleStyleSheet()
    search_url = "https://www.virustotal.com/gui/search?query=" + urllib.parse.quote(url, safe="")
    for intento_actual in range(1, intentos + 1):
        try:
            driver = DriverManager.get_driver()
            if not driver:
                mensaje = "No se pudo iniciar el navegador."
                warn(mensaje)
                _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)
                return False
            time.sleep(random.uniform(1.5, 3.5))
            driver.get(search_url)
            time.sleep(5)
            texto_pagina, encontro_marcador = esperar_reporte_completo(driver, timeout=40)
            if not encontro_marcador:
                if intento_actual < intentos:
                    warn(f"No aparecio la lista de motores (intento {intento_actual}/{intentos}). Reintentando...")
                    time.sleep(random.uniform(2.5, 5))
                    continue
                mensaje = "Tiempo de espera agotado: VirusTotal nunca mostro la lista de motores."
                warn(mensaje)
                _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)
                _guardar_debug_html(driver.page_source, texto_pagina)
                return False
            resumen = analizar_texto_virustotal(texto_pagina)
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
                    warn(f"0 motores leidos (intento {intento_actual}/{intentos}). Reintentando...")
                    time.sleep(random.uniform(2.5, 5))
                    continue
                return False
            return True
        except WebDriverException as e:
            if intento_actual < intentos:
                warn(f"Error de WebDriver (intento {intento_actual}/{intentos}): {e}. Reintentando...")
                DriverManager._driver = None
                time.sleep(3)
                continue
            mensaje = "Error al verificar en VirusTotal (WebDriver): " + str(e) + "\n"
            warn(mensaje)
            _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)
            return False
        except Exception as e:
            mensaje = "Error inesperado al verificar en VirusTotal: " + str(e) + "\n"
            warn(mensaje)
            _escribir_salidas(mensaje, archivo_txt, elementos_pdf, styles)
            return False
    return False

# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------

def construir_pdf(nombre_archivo, titulo, elementos_pdf):
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
        info("Texto extraido guardado en: " + debug_txt)

def analizar(url, archivo_txt=None, elementos_pdf=None):
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

def analizar_all(url, archivo_txt=None, elementos_pdf=None, limite=None):
    links_crudos = obtener_links(url)
    if isinstance(links_crudos, str):
        print(links_crudos)
        _escribir_salidas(links_crudos, archivo_txt, elementos_pdf, getSampleStyleSheet())
        return
    links = normalizar_links(links_crudos, url, limite=limite)
    styles = getSampleStyleSheet()
    descartados = len(links_crudos) - len(links)
    info(f"Enlaces encontrados: {len(links_crudos)} | analizables: {len(links)} | descartados: {descartados}")
    if archivo_txt:
        archivo_txt.write("Analisis completo de enlaces\n" + "=" * 50 + "\n\n")
    if elementos_pdf is not None:
        elementos_pdf.append(Paragraph("Analisis completo de enlaces", styles["Heading2"]))
        elementos_pdf.append(Spacer(1, 6))
    for idx, (texto, link) in enumerate(links):
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
        if idx < len(links) - 1:
            time.sleep(random.uniform(3, 7))
    DriverManager.cerrar()

def analizar_lista_manual(urls, archivo_txt=None, elementos_pdf=None):
    styles = getSampleStyleSheet()
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
    for idx, link in enumerate(urls_limpias):
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
        if idx < len(urls_limpias) - 1:
            time.sleep(random.uniform(3, 7))
    DriverManager.cerrar()

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    formato = "txt"
    if len(sys.argv) > 1:
        formato = sys.argv[1]
    elif "XONIWEB_FORMATO" in os.environ:
        formato = os.environ["XONIWEB_FORMATO"]
    try:
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
                    limite_txt = input("Maximo de enlaces a analizar de esa pagina (Enter = sin limite): ").strip()
                    if limite_txt.isdigit() and int(limite_txt) > 0:
                        limite_enlaces = int(limite_txt)
            else:
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
    finally:
        DriverManager.cerrar()

if __name__ == "__main__":
    main()