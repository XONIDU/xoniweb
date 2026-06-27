#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XONI-WEB 2026 - Analizador de URLs (sin API Key)
Usa busqueda web publica de VirusTotal con Selenium
Desarrollado por: Darian Alberto Camacho Salas & Oscar Rodolfo Barragan Perez
#Somos XONINDU
"""

import requests
from bs4 import BeautifulSoup
from datetime import datetime
import time
import re
import os
import urllib.parse
import sys
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER

# Intentar importar Selenium
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, NoSuchElementException
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("Selenium no disponible. Instala: pip install selenium webdriver-manager")

# Intentar importar reportlab para PDF
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("ReportLab no disponible. Instala: pip install reportlab")

# Color de Texto (rojo por defecto)
def color(text):
    print("\033[1;31m" + text + "\033[0m")

def get_webdriver():
    """Configura y retorna un driver de Chrome headless"""
    if not SELENIUM_AVAILABLE:
        return None
    
    try:
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--disable-blink-features=AutomationControlled')
        options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        
        try:
            # Metodo 1: WebDriver Manager
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
            return driver
        except:
            # Metodo 2: Driver del sistema
            try:
                service = Service('/usr/bin/chromedriver')
                driver = webdriver.Chrome(service=service, options=options)
                return driver
            except:
                # Metodo 3: Driver en PATH
                try:
                    driver = webdriver.Chrome(options=options)
                    return driver
                except:
                    # Metodo 4: Intentar con chromium-browser
                    options.binary_location = '/usr/bin/chromium'
                    driver = webdriver.Chrome(options=options)
                    return driver
    except Exception as e:
        print("Error configurando WebDriver: " + str(e))
        return None

def verificar_virus_selenium(url, archivo_txt=None, archivo_pdf=None, elementos_pdf=None):
    """Verifica URL usando Selenium"""
    print("Analizando con Selenium: " + url)
    
    driver = None
    try:
        search_url = "https://www.virustotal.com/gui/search?query=" + urllib.parse.quote(url, safe='')
        print("Accediendo a: " + search_url)
        
        driver = get_webdriver()
        if not driver:
            mensaje = "No se pudo iniciar el navegador. Verifica las dependencias.\n"
            print(mensaje)
            if archivo_txt:
                archivo_txt.write(mensaje)
            if archivo_pdf and elementos_pdf is not None:
                elementos_pdf.append(Paragraph(mensaje, getSampleStyleSheet()['Normal']))
            return
        
        driver.get(search_url)
        time.sleep(5)
        
        try:
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
        except TimeoutException:
            mensaje = "Tiempo de espera agotado para VirusTotal\n"
            print(mensaje)
            if archivo_txt:
                archivo_txt.write(mensaje)
            if archivo_pdf and elementos_pdf is not None:
                elementos_pdf.append(Paragraph(mensaje, getSampleStyleSheet()['Normal']))
            driver.quit()
            return
        
        html = driver.page_source
        soup = BeautifulSoup(html, 'html.parser')
        
        stats = {
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'undetected': 0
        }
        
        page_text = soup.get_text()
        
        patterns = {
            'malicious': r'(?:malicious|malware)\s*[:\s]*(\d+)',
            'suspicious': r'suspicious\s*[:\s]*(\d+)',
            'harmless': r'(?:harmless|clean)\s*[:\s]*(\d+)',
            'undetected': r'undetected\s*[:\s]*(\d+)'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, page_text, re.IGNORECASE)
            if match:
                stats[key] = int(match.group(1))
        
        # Si no se encontraron estadisticas, buscar indicadores
        if sum(stats.values()) == 0:
            malicious_indicators = ['malware', 'malicious', 'phishing', 'trojan', 'virus']
            harmless_indicators = ['clean', 'harmless', 'safe']
            
            for indicator in malicious_indicators:
                if indicator in page_text.lower():
                    stats['malicious'] = max(stats['malicious'], 1)
                    break
            for indicator in harmless_indicators:
                if indicator in page_text.lower() and stats['malicious'] == 0:
                    stats['harmless'] = max(stats['harmless'], 1)
                    break
        
        mensaje = "\nResultados para " + url + ":\n"
        mensaje += "  - Maliciosos: " + str(stats['malicious']) + "\n"
        mensaje += "  - Sospechosos: " + str(stats['suspicious']) + "\n"
        mensaje += "  - Limpios: " + str(stats['harmless']) + "\n"
        mensaje += "  - No detectados: " + str(stats['undetected']) + "\n"
        
        if stats['malicious'] > 0:
            mensaje += "ADVERTENCIA! La pagina contiene detecciones maliciosas.\n"
        else:
            mensaje += "La pagina esta limpia de virus.\n"
        
        print(mensaje)
        if archivo_txt:
            archivo_txt.write(mensaje + "\n")
        if archivo_pdf and elementos_pdf is not None:
            styles = getSampleStyleSheet()
            for line in mensaje.split('\n'):
                if line.strip():
                    elementos_pdf.append(Paragraph(line, styles['Normal']))
                    elementos_pdf.append(Spacer(1, 6))
        
        # Guardar HTML para depuracion
        debug_dir = "debug_vt"
        if not os.path.exists(debug_dir):
            os.makedirs(debug_dir)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        debug_file = debug_dir + "/vt_" + timestamp + ".html"
        with open(debug_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print("HTML guardado en: " + debug_file)
        
    except Exception as e:
        mensaje = "Error al verificar en VirusTotal: " + str(e) + "\n"
        print(mensaje)
        if archivo_txt:
            archivo_txt.write(mensaje)
        if archivo_pdf and elementos_pdf is not None:
            elementos_pdf.append(Paragraph(mensaje, getSampleStyleSheet()['Normal']))
    
    finally:
        if driver:
            driver.quit()

def obtener_links(url):
    """Obtiene todos los enlaces de una pagina web"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        print("URL corregida a: " + url)
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        respuesta = requests.get(url, headers=headers, timeout=10)
        respuesta.raise_for_status()
        soup = BeautifulSoup(respuesta.text, 'html.parser')
        enlaces = [(a.get_text(strip=True), a['href']) for a in soup.find_all('a', href=True)]
        return enlaces
    except requests.RequestException as e:
        return 'Error al acceder a la pagina: ' + str(e)

def generar_pdf(nombre_archivo, titulo, contenido):
    """Genera un PDF con el contenido del reporte"""
    if not REPORTLAB_AVAILABLE:
        print("ReportLab no instalado. No se pudo generar PDF.")
        return False
    
    try:
        doc = SimpleDocTemplate(nombre_archivo, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Estilo personalizado para titulo
        titulo_style = ParagraphStyle(
            'TituloStyle',
            parent=styles['Heading1'],
            fontSize=16,
            alignment=TA_CENTER,
            spaceAfter=20
        )
        
        elementos = []
        
        # Titulo
        elementos.append(Paragraph(titulo, titulo_style))
        elementos.append(Spacer(1, 12))
        
        # Contenido
        for linea in contenido:
            if linea.strip():
                if linea.startswith('==') or linea.startswith('---'):
                    # Subtitulos
                    elementos.append(Paragraph(linea, styles['Heading2']))
                    elementos.append(Spacer(1, 6))
                else:
                    # Texto normal
                    elementos.append(Paragraph(linea, styles['Normal']))
                    elementos.append(Spacer(1, 4))
        
        doc.build(elementos)
        return True
    except Exception as e:
        print("Error generando PDF: " + str(e))
        return False

def analizar(url, archivo_txt=None, archivo_pdf=None, elementos_pdf=None):
    """Analiza una URL: extrae enlaces y verifica virus"""
    links = obtener_links(url)
    if isinstance(links, str):
        print(links)
        if archivo_txt:
            archivo_txt.write(links + "\n")
        if archivo_pdf and elementos_pdf is not None:
            elementos_pdf.append(Paragraph(links, getSampleStyleSheet()['Normal']))
        return
    
    # Escribir en TXT
    if archivo_txt:
        archivo_txt.write("Enlaces encontrados\n")
        archivo_txt.write("=" * 50 + "\n\n")
    
    # Agregar a PDF
    if archivo_pdf and elementos_pdf is not None:
        elementos_pdf.append(Paragraph("Enlaces encontrados", getSampleStyleSheet()['Heading2']))
        elementos_pdf.append(Spacer(1, 6))
    
    for texto, link in links:
        if link.startswith('/'):
            link = url.rstrip('/') + link
        linea = "Texto: " + texto + "\nEnlace: " + link + "\n\n"
        print(linea)
        if archivo_txt:
            archivo_txt.write(linea)
        if archivo_pdf and elementos_pdf is not None:
            elementos_pdf.append(Paragraph("Texto: " + texto, getSampleStyleSheet()['Normal']))
            elementos_pdf.append(Paragraph("Enlace: " + link, getSampleStyleSheet()['Normal']))
            elementos_pdf.append(Spacer(1, 6))
    
    # Seccion de virus
    if archivo_txt:
        archivo_txt.write("\nResultado del analisis de virus\n")
        archivo_txt.write("=" * 50 + "\n\n")
    if archivo_pdf and elementos_pdf is not None:
        elementos_pdf.append(Spacer(1, 12))
        elementos_pdf.append(Paragraph("Resultado del analisis de virus", getSampleStyleSheet()['Heading2']))
        elementos_pdf.append(Spacer(1, 6))
    
    verificar_virus_selenium(url, archivo_txt, archivo_pdf, elementos_pdf)

def analizar_all(url, archivo_txt=None, archivo_pdf=None, elementos_pdf=None):
    """Analiza todos los enlaces de una URL"""
    links = obtener_links(url)
    if isinstance(links, str):
        print(links)
        if archivo_txt:
            archivo_txt.write(links + "\n")
        if archivo_pdf and elementos_pdf is not None:
            elementos_pdf.append(Paragraph(links, getSampleStyleSheet()['Normal']))
        return
    
    if archivo_txt:
        archivo_txt.write("Analisis completo de enlaces\n")
        archivo_txt.write("=" * 50 + "\n\n")
    if archivo_pdf and elementos_pdf is not None:
        elementos_pdf.append(Paragraph("Analisis completo de enlaces", getSampleStyleSheet()['Heading2']))
        elementos_pdf.append(Spacer(1, 6))
    
    for texto, link in links:
        if link.startswith('/'):
            link = url.rstrip('/') + link
        print("Analizando enlace: " + link)
        if archivo_txt:
            archivo_txt.write("Analizando enlace: " + link + "\n")
        if archivo_pdf and elementos_pdf is not None:
            elementos_pdf.append(Paragraph("Analizando enlace: " + link, getSampleStyleSheet()['Normal']))
            elementos_pdf.append(Spacer(1, 6))
        verificar_virus_selenium(link, archivo_txt, archivo_pdf, elementos_pdf)
        if archivo_txt:
            archivo_txt.write("\n" + "-" * 40 + "\n\n")
        if archivo_pdf and elementos_pdf is not None:
            elementos_pdf.append(Paragraph("-" * 40, getSampleStyleSheet()['Normal']))
            elementos_pdf.append(Spacer(1, 6))

def main():
    """Funcion principal"""
    # Obtener formato de reporte desde argumento o variable de entorno
    formato = 'txt'
    if len(sys.argv) > 1:
        formato = sys.argv[1]
    elif 'XONIWEB_FORMATO' in os.environ:
        formato = os.environ['XONIWEB_FORMATO']
    
    while True:
        color("""
 ╔════════════════════════════════════════════════════════╗
 ║                    XONI-WEB 2026                      ║
 ║              Analisis de URLs sin API Key             ║
 ║          Web Scraping + VirusTotal Publico           ║
 ║                                                      ║
 ║         Desarrollado por: XONIDU - FES UNAM         ║
 ╚════════════════════════════════════════════════════════╝
        """)
        
        nombre_reporte = input("Nombre del Reporte (sin extension): ")
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
Opcion: """)

        # Determinar formatos a generar
        generar_txt = formato in ['txt', 'ambos']
        generar_pdf = formato in ['pdf', 'ambos'] and REPORTLAB_AVAILABLE
        
        if formato == 'pdf' and not REPORTLAB_AVAILABLE:
            print("ReportLab no instalado. Generando solo TXT.")
            generar_txt = True
            generar_pdf = False
        
        # Preparar archivos
        archivo_txt = None
        archivo_pdf = None
        elementos_pdf = []
        nombre_txt = nombre_reporte + ".txt"
        nombre_pdf = nombre_reporte + ".pdf"
        
        # Abrir archivo TXT
        if generar_txt:
            archivo_txt = open(nombre_txt, 'w', encoding='utf-8')
            archivo_txt.write("Reporte de analisis para: " + url + "\n")
            archivo_txt.write("=" * 60 + "\n\n")
        
        # Preparar PDF
        if generar_pdf:
            # El contenido se guarda en elementos_pdf y se escribe al final
            pass
        
        # Escribir fecha y hora
        ahora = datetime.now()
        fecha = ahora.strftime("%Y-%m-%d")
        hora = ahora.strftime("%H:%M:%S")
        print("\nFecha: " + fecha + "\nHora: " + hora)
        
        if archivo_txt:
            archivo_txt.write("Fecha: " + fecha + "\nHora: " + hora + "\n\n")
            archivo_txt.write("=" * 60 + "\n\n")
        
        if generar_pdf:
            elementos_pdf.append(Paragraph("Fecha: " + fecha, getSampleStyleSheet()['Normal']))
            elementos_pdf.append(Paragraph("Hora: " + hora, getSampleStyleSheet()['Normal']))
            elementos_pdf.append(Spacer(1, 12))
        
        # Ejecutar analisis
        if opcion == "0":
            analizar(url, archivo_txt, archivo_pdf, elementos_pdf)
        elif opcion == "1":
            analizar_all(url, archivo_txt, archivo_pdf, elementos_pdf)
        else:
            print("Opcion invalida.\n")
            if archivo_txt:
                archivo_txt.write("Opcion invalida.\n")
            if generar_pdf:
                elementos_pdf.append(Paragraph("Opcion invalida.", getSampleStyleSheet()['Normal']))
        
        # Cerrar archivo TXT
        if archivo_txt:
            archivo_txt.close()
            print("\nReporte TXT guardado en: " + nombre_txt)
        
        # Generar PDF
        if generar_pdf:
            titulo = "XONI-WEB - Reporte de Analisis"
            if generar_pdf(nombre_pdf, titulo, [p.text for p in elementos_pdf if hasattr(p, 'text')]):
                print("Reporte PDF guardado en: " + nombre_pdf)
            else:
                print("Error generando PDF")
        
        # Mostrar resumen
        print("\n" + "=" * 60)
        print("Resumen de archivos generados:")
        if generar_txt:
            print("  - " + nombre_txt)
        if generar_pdf and REPORTLAB_AVAILABLE:
            print("  - " + nombre_pdf)
        print("=" * 60 + "\n")
        
        continuar = input("Analizar otra URL? (s/n): ").lower()
        if continuar != 's':
            print("\nHasta luego! - #Somos XONINDU")
            break

if __name__ == "__main__":
    main()
