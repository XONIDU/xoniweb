#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XONIWEB - Logica de analisis
=============================
Analiza URLs con fuentes confiables y gratuitas, sin APIs ni llaves
(ver xoniweb_fuentes.py): OpenPhish, Spamhaus DBL, SURBL, heuristica
local y fetch HTTP. Si hay un navegador disponible (Selenium +
Chromium, por ejemplo en Docker), VirusTotal publico se suma como una
fuente mas, mostrando solo sus motores confiables.

Genera reportes en TXT y PDF (ReportLab).

Exporta:
    SELENIUM_AVAILABLE (bool)
    REPORTLAB_AVAILABLE (bool)
    ejecutar_analisis_completo(urls, modo, nombre_reporte, formato, archivo_txt_path, email_destinatario) -> (resultado, rutas)
    obtener_links(url) -> list[str]
    normalizar_links(links) -> list[str]
"""

import hashlib
import os
import re
import shutil
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

from xoniweb_fuentes import analizar_url_fuentes

# --------------------------------------------------------------------------
# Disponibilidad de dependencias opcionales
# --------------------------------------------------------------------------

SELENIUM_AVAILABLE = False
REPORTLAB_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except Exception:
    SELENIUM_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle)
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------

def _sha256_url(url):
    """Calcula el hash SHA-256 de una URL (usado por VirusTotal como ID)."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def _limpiar_texto(texto):
    """Limpia espacios y caracteres de control de un texto."""
    if not texto:
        return ""
    return re.sub(r"\s+", " ", str(texto)).strip()


def _extraer_numero(texto):
    """Extrae el primer numero entero encontrado en un texto."""
    if texto is None:
        return 0
    m = re.search(r"(\d+)", str(texto))
    return int(m.group(1)) if m else 0


# --------------------------------------------------------------------------
# Selenium: navegador y extraccion de VirusTotal publico
# --------------------------------------------------------------------------

def _crear_driver():
    """Crea y devuelve un driver de Chrome headless con timeouts estrictos."""
    opciones = webdriver.ChromeOptions()
    opciones.add_argument("--headless=new")
    opciones.add_argument("--no-sandbox")
    opciones.add_argument("--disable-dev-shm-usage")
    opciones.add_argument("--disable-gpu")
    opciones.add_argument("--window-size=1920,1080")
    opciones.add_argument("--disable-blink-features=AutomationControlled")
    opciones.add_argument(
        "--user-agent=Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
    )
    # En Docker el chromedriver viene instalado por apt (paquete
    # chromium-driver): usarlo antes que descargar uno con
    # webdriver-manager, que necesita detectar la version de Chrome.
    ruta_driver = shutil.which("chromedriver")
    if ruta_driver:
        servicio = Service(ruta_driver)
    else:
        servicio = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=servicio, options=opciones)
    # Timeouts estrictos para que nunca se quede bloqueado para siempre
    driver.set_page_load_timeout(25)
    driver.implicitly_wait(8)
    driver.set_script_timeout(15)
    return driver


def _consulta_virustotal_publico(driver, url, timeout=30):
    """
    Consulta la interfaz publica de VirusTotal para una URL y devuelve
    un diccionario con los resultados del analisis.
    """
    url_hash = _sha256_url(url)
    vt_url = f"https://www.virustotal.com/gui/url/{url_hash}"

    resultado = {
        "url": url,
        "estado": "error",
        "motivo": None,
        "resumen": None,
    }

    try:
        driver.get(vt_url)
    except Exception:
        # Timeout de carga de pagina u otro error de navegacion
        resultado["estado"] = "error"
        resultado["motivo"] = "No se pudo cargar VirusTotal (timeout o bloqueo)"
        resultado["resumen"] = None
        return resultado

    try:
        # Esperar breve a que renderice el shadow DOM
        time.sleep(2)

        # Intentar detectar si la URL no ha sido analizada antes
        pagina = driver.page_source
        if "no se ha encontrado" in pagina.lower() or "not found" in pagina.lower():
            resultado["estado"] = "ok"
            resultado["motivo"] = "URL no analizada previamente en VirusTotal"
            resultado["resumen"] = {
                "total_amenazas": 0,
                "total_motores_analizados": 0,
                "ultimo_analisis": None,
                "tipos_detectados": [],
                "motores_amenaza": [],
            }
            return resultado

        # Extraer datos del shadow DOM de VirusTotal
        # VirusTotal usa web components; intentamos extraer via JS
        script_detecciones = """
        var resultado = {};
        try {
            var detections = document.querySelector('vt-ui-detections');
            if (detections && detections.shadowRoot) {
                var malicious = detections.shadowRoot.querySelector('.detections-malicious');
                var suspicious = detections.shadowRoot.querySelector('.detections-suspicious');
                var harmless = detections.shadowRoot.querySelector('.detections-harmless');
                var undetected = detections.shadowRoot.querySelector('.detections-undetected');
                resultado.total_amenazas = parseInt(malicious?.textContent?.match(/\\d+/)?.[0]) || 0;
                resultado.total_sospechosas = parseInt(suspicious?.textContent?.match(/\\d+/)?.[0]) || 0;
                resultado.total_inofensivas = parseInt(harmless?.textContent?.match(/\\d+/)?.[0]) || 0;
                resultado.total_sin_detectar = parseInt(undetected?.textContent?.match(/\\d+/)?.[0]) || 0;
            }
        } catch(e) {}
        return resultado;
        """

        try:
            detecciones = driver.execute_script(script_detecciones)
        except Exception:
            detecciones = {}

        total_amenazas = detecciones.get("total_amenazas", 0)
        total_sospechosas = detecciones.get("total_sospechosas", 0)
        total_inofensivas = detecciones.get("total_inofensivas", 0)
        total_sin_detectar = detecciones.get("total_sin_detectar", 0)
        total_motores = total_amenazas + total_sospechosas + total_inofensivas + total_sin_detectar

        # Extraer detalles de motores detectados
        script_motores = """
        var motores = [];
        try {
            var filas = document.querySelectorAll('vt-ui-detection-row');
            filas.forEach(function(fila) {
                var motor = fila.querySelector('.detection-engine')?.textContent?.trim() || '';
                var categoria = fila.querySelector('.detection-category')?.textContent?.trim() || '';
                var resultado_motor = fila.querySelector('.detection-result')?.textContent?.trim() || '';
                if (motor) {
                    motores.push({motor: motor, categoria: categoria, resultado: resultado_motor});
                }
            });
        } catch(e) {}
        return motores;
        """

        try:
            motores_raw = driver.execute_script(script_motores)
        except Exception:
            motores_raw = []

        motores_amenaza = []
        tipos_detectados = set()
        for m in motores_raw:
            motor = m.get("motor", "")
            categoria = m.get("categoria", "")
            res = m.get("resultado", "")
            if categoria.lower() in ("malicious", "malware", "phishing", "suspicious"):
                motores_amenaza.append((motor, res, categoria.lower()))
                if categoria.lower() in ("malware", "phishing"):
                    tipos_detectados.add(categoria.lower())

        # Ultimo analisis
        script_fecha = """
        var fecha = '';
        try {
            var elem = document.querySelector('.last-analysis-date') ||
                       document.querySelector('[data-testid="last-analysis-date"]');
            if (elem) fecha = elem.textContent?.trim() || '';
        } catch(e) {}
        return fecha;
        """

        try:
            ultimo_analisis = driver.execute_script(script_fecha)
        except Exception:
            ultimo_analisis = ""

        resultado["estado"] = "ok"
        resultado["motivo"] = None
        resultado["resumen"] = {
            "total_amenazas": total_amenazas,
            "total_motores_analizados": total_motores,
            "ultimo_analisis": _limpiar_texto(ultimo_analisis) or "Desconocido",
            "tipos_detectados": sorted(tipos_detectados),
            "motores_amenaza": motores_amenaza,
        }
    except Exception as exc:
        resultado["estado"] = "error"
        resultado["motivo"] = str(exc)
        resultado["resumen"] = None

    return resultado


# --------------------------------------------------------------------------
# Obtener enlaces de una URL principal (modo principal)
# --------------------------------------------------------------------------

def obtener_links(url):
    """
    Dada una URL principal, devuelve la lista de enlaces encontrados en esa pagina.
    Usa requests + beautifulsoup4 si estan disponibles, de lo contrario devuelve [url].
    """
    try:
        import requests
        from bs4 import BeautifulSoup
        resp = requests.get(url, timeout=15,
                            headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        enlaces = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:"):
                continue
            enlaces.append(href)
        return enlaces
    except Exception:
        return [url]


def normalizar_links(links, base_url=None):
    """Normaliza una lista de enlaces: absoluta, sin fragmentos, sin duplicados."""
    normalizados = []
    vistos = set()
    for link in links:
        link = link.strip()
        if not link:
            continue
        if link.startswith("//"):
            link = "https:" + link
        elif link.startswith("/") and base_url:
            parsed = urlparse(base_url)
            link = f"{parsed.scheme}://{parsed.netloc}{link}"
        elif not link.startswith(("http://", "https://")):
            if base_url:
                parsed = urlparse(base_url)
                link = f"{parsed.scheme}://{parsed.netloc}/{link.lstrip('/')}"
            else:
                link = "https://" + link
        # quitar fragmento
        link = link.split("#")[0]
        if link not in vistos:
            vistos.add(link)
            normalizados.append(link)
    return normalizados


# --------------------------------------------------------------------------
# Reporte TXT
# --------------------------------------------------------------------------

def _generar_reporte_txt(ruta_txt, registros, total, titulo):
    """Genera un reporte TXT y devuelve True si tuvo exito."""
    try:
        with open(ruta_txt, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("XONIWEB - Reporte de Analisis de URLs\n")
            f.write("=" * 70 + "\n")
            f.write(f"Titulo: {titulo}\n")
            f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"URLs analizadas: {total}\n")
            f.write("Metodo: fuentes confiables gratuitas sin APIs "
                    "(OpenPhish, Spamhaus DBL, SURBL, heuristica, fetch) "
                    "+ VirusTotal publico si hay navegador\n")
            f.write("=" * 70 + "\n\n")

            for i, r in enumerate(registros, 1):
                f.write(f"[{i}] {r['url']}\n")
                f.write(f"    Estado: {r.get('estado', 'desconocido')}\n")
                if r.get("motivo"):
                    f.write(f"    Motivo: {r['motivo']}\n")
                res = r.get("resumen")
                if res:
                    f.write(f"    Amenazas detectadas: {res.get('total_amenazas', 0)}\n")
                    f.write(f"    Motores analizados: {res.get('total_motores_analizados', 0)}\n")
                    edad = res.get("edad_dominio_dias")
                    nivel = res.get("nivel_analisis")
                    if edad is not None:
                        f.write(f"    Edad del dominio: {edad} dias\n")
                    if nivel:
                        f.write(f"    Nivel de analisis: {nivel}\n")
                    f.write(f"    Ultimo analisis: {res.get('ultimo_analisis', 'N/A')}\n")
                    tipos = res.get("tipos_detectados", [])
                    if tipos:
                        f.write(f"    Tipos de amenaza: {', '.join(tipos)}\n")
                    motores = res.get("motores_amenaza", [])
                    if motores:
                        f.write("    Motores que detectaron:\n")
                        for motor, res_motor, cat in motores:
                            f.write(f"      - {motor}: {res_motor} ({cat})\n")
                else:
                    f.write("    Sin datos disponibles\n")
                f.write("-" * 70 + "\n\n")

            f.write("=" * 70 + "\n")
            f.write("Fin del reporte\n")
            f.write("=" * 70 + "\n")
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# Reporte PDF
# --------------------------------------------------------------------------

def _pie_pagina_pdf(canvas, doc):
    """Pie de pagina del reporte: credito + numero de pagina."""
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#5b6b84"))
    canvas.drawCentredString(doc.pagesize[0] / 2.0, 12 * mm,
                             "Desarrollado por D. Alberto Camcho S.")
    canvas.drawRightString(doc.pagesize[0] - 15 * mm, 12 * mm,
                           f"Página {canvas.getPageNumber()}")
    canvas.restoreState()


def _estilo_tabla_pdf():
    """Estilo comun para las tablas del reporte PDF."""
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f5f5f5")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ])


def _generar_reporte_pdf(ruta_pdf, registros, total, titulo):
    """Genera un reporte PDF profesional (vertical, carta) y devuelve True
    si tuvo exito. Dos tablas: resumen por URL y motores que detectaron
    algo, con pie de pagina en todas las paginas."""
    if not REPORTLAB_AVAILABLE:
        return False
    try:
        from collections import Counter
        try:
            from xoniweb_web import _riesgo as _riesgo_web
        except Exception:
            _riesgo_web = None

        # Vertical (carta): el ancho util es 215.9 mm menos los margenes.
        doc = SimpleDocTemplate(ruta_pdf, pagesize=letter,
                                leftMargin=15 * mm, rightMargin=15 * mm,
                                topMargin=15 * mm, bottomMargin=18 * mm,
                                title=f"XONIWEB - {titulo}",
                                author="D. Alberto Camcho S.")
        styles = getSampleStyleSheet()
        estilo_titulo = ParagraphStyle(
            "Titulo", parent=styles["Title"], fontSize=18,
            textColor=colors.HexColor("#1a237e"), spaceAfter=2,
        )
        estilo_sub = ParagraphStyle(
            "Sub", parent=styles["Normal"], fontSize=9, leading=12,
            textColor=colors.HexColor("#333333"), spaceAfter=10,
        )
        estilo_seccion = ParagraphStyle(
            "Seccion", parent=styles["Heading2"], fontSize=12,
            textColor=colors.HexColor("#1a237e"), spaceBefore=12, spaceAfter=6,
        )
        estilo_celda = ParagraphStyle(
            "Celda", parent=styles["Normal"], fontSize=7.5, leading=9,
        )
        estilo_celda_ch = ParagraphStyle(
            "CeldaCh", parent=estilo_celda, fontSize=7, leading=8.5,
        )

        # Resumen de veredictos.
        niveles = []
        for r in registros:
            niveles.append(_riesgo_web(r) if _riesgo_web
                           else r.get("estado", "SIN DATOS"))
        conteo = Counter(niveles)
        resumen_txt = "  ·  ".join(
            f"{k}: {conteo.get(k, 0)}" for k in
            ("LIMPIO", "REVISAR", "RIESGO ALTO", "SIN DATOS"))

        elementos = []
        elementos.append(Paragraph("XONIWEB", estilo_titulo))
        elementos.append(Paragraph(
            f"Reporte de Análisis de URLs — {_limpiar_texto(titulo)}<br/>"
            f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
            f"URLs analizadas: {total}  |  Método: fuentes gratuitas sin APIs "
            f"(+ VirusTotal si hay navegador)<br/>"
            f"{resumen_txt}",
            estilo_sub,
        ))

        # Tabla 1: resumen por URL.
        elementos.append(Paragraph("Resumen por URL", estilo_seccion))
        datos = [["#", "URL", "Estado", "Motores", "Último análisis",
                  "Tipos de amenaza"]]
        for i, r in enumerate(registros, 1):
            res = r.get("resumen") or {}
            tipos = res.get("tipos_detectados") or []
            datos.append([
                str(i),
                Paragraph(_limpiar_texto(r["url"]), estilo_celda),
                _riesgo_web(r) if _riesgo_web else r.get("estado", "-"),
                f"{res.get('total_amenazas', 0)} / {res.get('total_motores_analizados', 0)}",
                Paragraph(_limpiar_texto(res.get("ultimo_analisis", "-")),
                          estilo_celda_ch),
                Paragraph(_limpiar_texto(", ".join(tipos) if tipos else "-"),
                          estilo_celda_ch),
            ])
        tabla = Table(datos, colWidths=[8 * mm, 58 * mm, 22 * mm, 16 * mm,
                                        32 * mm, 34 * mm], repeatRows=1)
        tabla.setStyle(_estilo_tabla_pdf())
        elementos.append(tabla)

        # Tabla 2: motores que detectaron algo.
        elementos.append(Paragraph("Motores que detectaron algo", estilo_seccion))
        detalle = [["URL", "Motor", "Detalle", "Categoría"]]
        hay = False
        for r in registros:
            res = r.get("resumen") or {}
            for motor, det, cat in (res.get("motores_amenaza") or []):
                hay = True
                detalle.append([
                    Paragraph(_limpiar_texto(r["url"]), estilo_celda_ch),
                    Paragraph(_limpiar_texto(motor), estilo_celda),
                    Paragraph(_limpiar_texto(det or "-"), estilo_celda),
                    Paragraph(_limpiar_texto(cat or "-"), estilo_celda_ch),
                ])
        if hay:
            tabla2 = Table(detalle, colWidths=[45 * mm, 30 * mm, 72 * mm, 23 * mm],
                           repeatRows=1)
            tabla2.setStyle(_estilo_tabla_pdf())
            elementos.append(tabla2)
        else:
            elementos.append(Paragraph(
                "Ningún motor detectó amenazas en este análisis.",
                styles["Normal"]))

        doc.build(elementos, onFirstPage=_pie_pagina_pdf,
                  onLaterPages=_pie_pagina_pdf)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# Envio de correo (opcional, msmtp)
# --------------------------------------------------------------------------

def _enviar_correo(destinatario, ruta_pdf, ruta_txt):
    """Intenta enviar el reporte PDF por correo usando msmtp."""
    try:
        import subprocess
        mensaje = (
            "Subject: XONIWEB - Reporte de analisis de URLs\r\n"
            "To: " + destinatario + "\r\n"
            "\r\n"
            "Se adjunta el reporte de analisis de URLs generado por XONIWEB.\r\n"
        )
        with open(ruta_pdf, "rb") as f:
            pdf_b64 = ""
            import base64
            pdf_b64 = base64.b64encode(f.read()).decode("ascii")
        mensaje += f"\n--boundary_xoni\nContent-Type: application/pdf; name=reporte.pdf\n"
        mensaje += "Content-Transfer-Encoding: base64\n"
        mensaje += f"Content-Disposition: attachment; filename=reporte.pdf\n\n"
        # enviar en trozos de 76 chars
        for i in range(0, len(pdf_b64), 76):
            mensaje += pdf_b64[i:i+76] + "\n"
        mensaje += "--boundary_xoni--\n"

        proc = subprocess.run(
            ["msmtp", "-a", "default", destinatario],
            input=mensaje.encode("utf-8"),
            capture_output=True, timeout=30,
        )
        return proc.returncode == 0, "Enviado" if proc.returncode == 0 else proc.stderr.decode("utf-8", errors="ignore")[:200]
    except Exception as exc:
        return False, str(exc)


# --------------------------------------------------------------------------
# Funcion principal de analisis
# --------------------------------------------------------------------------

def ejecutar_analisis_completo(urls, modo="lista", nombre_reporte="reporte_xoniweb",
                               formato="ambos", archivo_txt_path=None, email_destinatario=None,
                               on_progress=None):
    """
    Ejecuta el analisis completo de una lista de URLs.

    Parametros:
        urls: lista de URLs a analizar
        modo: "lista" o "principal"
        nombre_reporte: ruta base del reporte (sin extension)
        formato: "txt", "pdf" o "ambos"
        archivo_txt_path: ruta opcional del archivo TXT (para uso interno del web)
        email_destinatario: correo opcional para enviar el reporte
        on_progress: callback(opcional) llamado tras cada URL con (hechos, totales)

    Devuelve:
        (resultado, rutas)
        resultado: dict con claves registros, total, pdf_error, email_enviado, email_mensaje
        rutas: dict con claves txt, pdf (rutas o None)
    """
    rutas = {"txt": None, "pdf": None}
    registros = []

    # Determinar el driver de Selenium (se reutiliza para todas las URLs)
    driver = None
    selenium_ok = SELENIUM_AVAILABLE
    if selenium_ok:
        try:
            driver = _crear_driver()
        except Exception:
            driver = None
            selenium_ok = False

    try:
        total_urls = len(urls)
        for idx, url in enumerate(urls, 1):
            registro = {"url": url, "estado": "error", "motivo": None, "resumen": None}

            if modo == "principal" and len(urls) == 1:
                # Modo principal: obtener enlaces de la URL y analizarlos
                try:
                    enlaces = obtener_links(url)
                    enlaces = normalizar_links(enlaces, base_url=url)
                    if enlaces:
                        # Analizar la URL principal primero con las fuentes
                        # confiables (VirusTotal solo si hay navegador).
                        registro = analizar_url_fuentes(
                            url,
                            driver=driver if selenium_ok else None,
                            vt_consulta=_consulta_virustotal_publico,
                        )
                        registros.append(registro)
                        # Analizar los enlaces encontrados
                        for enlace in enlaces[:20]:  # limitar a 20 enlaces
                            registros.append(analizar_url_fuentes(
                                enlace,
                                driver=driver if selenium_ok else None,
                                vt_consulta=_consulta_virustotal_publico,
                            ))
                    else:
                        registros.append(analizar_url_fuentes(
                            url,
                            driver=driver if selenium_ok else None,
                            vt_consulta=_consulta_virustotal_publico,
                        ))
                except Exception as exc:
                    registro = {"url": url, "estado": "error",
                                "motivo": str(exc), "resumen": None}
                    registros.append(registro)
            else:
                # Modo lista: analizar cada URL directamente con las
                # fuentes confiables (VirusTotal solo si hay navegador).
                registros.append(analizar_url_fuentes(
                    url,
                    driver=driver if selenium_ok else None,
                    vt_consulta=_consulta_virustotal_publico,
                ))

            # Reporte de progreso tras cada URL procesada
            if on_progress:
                try:
                    on_progress(idx, total_urls)
                except Exception:
                    pass

            # Pequeña pausa entre consultas para no saturar
            time.sleep(1)

    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

    # Generar reportes
    pdf_error = None

    # Ruta TXT
    if archivo_txt_path:
        ruta_txt = archivo_txt_path
    else:
        ruta_txt = nombre_reporte + ".txt"

    if formato in ("txt", "ambos"):
        if _generar_reporte_txt(ruta_txt, registros, len(registros),
                                modo.upper() + " - " + str(len(urls)) + " URL(s)"):
            rutas["txt"] = ruta_txt

    # Ruta PDF
    ruta_pdf = nombre_reporte + ".pdf"
    if formato in ("pdf", "ambos"):
        if REPORTLAB_AVAILABLE:
            if _generar_reporte_pdf(ruta_pdf, registros, len(registros),
                                      modo.upper() + " - " + str(len(urls)) + " URL(s)"):
                rutas["pdf"] = ruta_pdf
            else:
                pdf_error = "No se pudo generar el PDF"
        else:
            pdf_error = "ReportLab no disponible"

    # Envio de correo opcional
    email_enviado = False
    email_mensaje = None
    if email_destinatario and rutas.get("pdf"):
        email_enviado, email_mensaje = _enviar_correo(email_destinatario,
                                                       rutas["pdf"],
                                                       rutas.get("txt"))

    resultado = {
        "registros": registros,
        "total": len(registros),
        "pdf_error": pdf_error,
        "email_enviado": email_enviado,
        "email_mensaje": email_mensaje,
    }

    return resultado, rutas
