#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XONIWEB - Modo Web (Flask)
================================
Interfaz web profesional para el analizador de URLs (sin API Key de VirusTotal).

Rutas:
    GET  /                     Panel principal / dashboard
    GET  /analizar             Formulario de analisis (pegar URLs / subir archivo)
    POST /analizar             Iniciar analisis (redirige a resultado)
    POST /upload               Subir archivo (TXT/PDF/Excel) y extraer URLs
    GET  /resultado/<id>       Ver resultados de un analisis
    GET  /descargar/txt/<id>   Descargar reporte TXT
    GET  /descargar/pdf/<id>   Descargar reporte PDF
    GET  /setup                Configuracion inicial
    GET  /health               Estado del servidor

Arranque:
    python xoniweb_web.py           (Flask en puerto 5505)
    python start.py --web           (desde el lanzador, recomendado)
"""

import json
import os
import re
import shutil
import sys
import uuid
import threading
from datetime import datetime
from urllib.parse import urlparse

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, send_file, jsonify)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from xoniweb_core import (
    ejecutar_analisis_completo, SELENIUM_AVAILABLE, REPORTLAB_AVAILABLE,
    obtener_links, normalizar_links,
)

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"),
            static_folder=os.path.join(BASE_DIR, "static"))
app.secret_key = os.environ.get("XONIWEB_SECRET_KEY",
                                "xoniweb-dev-" + uuid.uuid4().hex[:16])

CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
REPORTES_DIR = os.path.join(BASE_DIR, "reportes")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(REPORTES_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)

CONFIG = {
    "setup_done": True,
    "port": 5505,
    "host": "0.0.0.0",
    "theme_default": "dark",
    "email": {"enabled": False, "sender": "", "app_password": "", "recipients": []},
}
if os.path.isfile(CONFIG_PATH):
    try:
        import json
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            CONFIG.update(json.load(f))
    except Exception:
        pass

# Estado de ejecuciones (en memoria, nada persistente en disco)
EJECUCIONES = {}
EJECUCIONES_LOCK = threading.Lock()

URL_RE = re.compile(r"https?://[^\s<>\)]+", re.IGNORECASE)
# Dominio sin protocolo: www.ejemplo.com, ejemplo.com, sub.dominio.org, etc.
DOMINIO_RE = re.compile(
    r"^(?:www\d*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s<>\)]*)?$"
)


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------

def _extraer_urls_texto(texto):
    """Extrae URLs de un texto plano (copiar-y-pegar o contenido de archivo)."""
    urls = []
    for m in URL_RE.finditer(texto):
        u = m.group(0).rstrip(".,;:!?)]}")
        if u not in urls:
            urls.append(u)
    # tambien lineas que sean solo URL sin protocolo (agregar https://)
    for linea in texto.splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#"):
            continue
        if linea.startswith(("http://", "https://")):
            continue
        if DOMINIO_RE.match(linea) and " " not in linea:
            u = "https://" + linea
            if u not in urls:
                urls.append(u)
    return urls


def _extraer_urls_de_pdf(ruta):
    """Extrae URLs de un PDF (opcional, requiere pypdf)."""
    urls = []
    try:
        from pypdf import PdfReader
        reader = PdfReader(ruta)
        for pagina in reader.pages:
            texto = pagina.extract_text() or ""
            urls.extend(_extraer_urls_texto(texto))
    except Exception:
        pass
    return urls


def _extraer_urls_de_excel(ruta):
    """Extrae URLs de un archivo Excel (opcional, requiere openpyxl)."""
    urls = []
    try:
        from openpyxl import load_workbook
        wb = load_workbook(ruta, read_only=True, data_only=True)
        for hoja in wb.worksheets:
            for fila in hoja.iter_rows(values_only=True):
                for celda in fila:
                    if celda is None:
                        continue
                    valor = str(celda).strip()
                    if not valor:
                        continue
                    urls.extend(_extraer_urls_texto(valor))
    except Exception:
        pass
    return urls


def _extraer_urls_de_archivo(ruta):
    """Extrae URLs de un archivo segun su extension."""
    ext = os.path.splitext(ruta)[1].lower()
    if ext == ".txt":
        try:
            with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
                return _extraer_urls_texto(f.read())
        except OSError:
            return []
    if ext == ".pdf":
        return _extraer_urls_de_pdf(ruta)
    if ext in (".xlsx", ".xls"):
        return _extraer_urls_de_excel(ruta)
    return []


def _riesgo(r):
    if r.get("estado") != "ok" or not r.get("resumen"):
        return "SIN DATOS"
    res = r["resumen"]
    n = res.get("total_amenazas", 0)
    if n == 0:
        return "LIMPIO"
    graves = sum(1 for _, _, cat in res.get("motores_amenaza", [])
                 if cat in ("malware", "phishing"))
    if n >= 3 or graves >= 2:
        return "RIESGO ALTO"
    return "REVISAR"


def _limpiar_reportes_previos():
    """Borra reportes y archivos subidos anteriores para no saturar el disco."""
    for directorio in (REPORTES_DIR, UPLOADS_DIR):
        if not os.path.isdir(directorio):
            continue
        for nombre in os.listdir(directorio):
            ruta = os.path.join(directorio, nombre)
            try:
                if os.path.isfile(ruta) or os.path.islink(ruta):
                    os.unlink(ruta)
                elif os.path.isdir(ruta):
                    shutil.rmtree(ruta)
            except Exception:
                pass


# --------------------------------------------------------------------------
# Rutas
# --------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html",
                           selenium=SELENIUM_AVAILABLE,
                           reportlab=REPORTLAB_AVAILABLE,
                           tema=CONFIG.get("theme_default", "dark"))


@app.route("/analizar", methods=["GET", "POST"])
def analizar():
    if request.method == "POST":
        urls_raw = request.form.get("urls", "") or ""
        urls = [u.strip() for u in _extraer_urls_texto(urls_raw)]
        # archivos subidos
        for key in ("archivo",):
            archivo = request.files.get(key)
            if archivo and archivo.filename:
                nombre = os.path.basename(archivo.filename)
                ruta = os.path.join(UPLOADS_DIR, nombre)
                archivo.save(ruta)
                urls.extend(_extraer_urls_de_archivo(ruta))
        # quitar duplicados preservando orden
        vistos = set()
        urls_unicas = []
        for u in urls:
            if u not in vistos:
                vistos.add(u)
                urls_unicas.append(u)
        urls = urls_unicas

        if not urls:
            flash("No se encontro ninguna URL valida.", "error")
            return redirect(url_for("analizar"))

        modo = request.form.get("modo", "lista")

        # Modo URL principal + subenlaces: extraer enlaces y mostrar preview antes de analizar
        if modo == "principal" and len(urls) == 1:
            url_principal = urls[0]
            try:
                enlaces = obtener_links(url_principal)
                enlaces = normalizar_links(enlaces, base_url=url_principal)
            except Exception:
                enlaces = [url_principal]

            # Calcular dominio original para filtrar prioridad externa
            dominio_original = ""
            try:
                from urllib.parse import urlparse
                dominio_original = urlparse(url_principal).netloc
            except Exception:
                pass

            clasificados = []
            for e in enlaces:
                try:
                    d = urlparse(e).netloc
                except Exception:
                    d = ""
                externo = bool(d) and d != dominio_original
                clasificados.append({"url": e, "externo": externo})

            # Ordenar: externos (dominio distinto) primero, luego internos
            clasificados.sort(key=lambda x: (not x["externo"], x["url"]))

            ej_id = uuid.uuid4().hex[:12]
            ahora = datetime.now()
            with EJECUCIONES_LOCK:
                EJECUCIONES[ej_id] = {
                    "id": ej_id, "estado": "preview", "inicio": ahora.strftime("%H:%M:%S"),
                    "fecha": ahora.strftime("%Y-%m-%d"),
                    "urls": [url_principal], "modo": modo, "total": 0,
                    "registros": [], "pdf": None, "txt": None,
                    "pdf_error": None, "titulo": url_principal,
                    "progreso": 0, "pasos_totales": len(clasificados),
                    "enlaces_preview": clasificados,
                    "dominio_original": dominio_original, "confirmado": False,
                }

            flash(f"Se encontraron {len(clasificados)} enlace(s). Selecciona cuales analizar.", "ok")
            return redirect(url_for("preview", id=ej_id))

        return _lanzar_analisis(urls, modo=modo)

    return render_template("analizar.html",
                           selenium=SELENIUM_AVAILABLE,
                           tema=CONFIG.get("theme_default", "dark"))


@app.route("/upload", methods=["POST"])
def upload():
    """Sube un archivo y devuelve las URLs extraidas (JSON)."""
    archivo = request.files.get("archivo")
    if not archivo or not archivo.filename:
        return jsonify({"ok": False, "mensaje": "No se recibio archivo", "urls": []})
    nombre = os.path.basename(archivo.filename)
    ruta = os.path.join(UPLOADS_DIR, nombre)
    archivo.save(ruta)
    urls = _extraer_urls_de_archivo(ruta)
    return jsonify({"ok": True, "archivo": nombre, "urls": urls,
                    "total": len(urls)})


def _lanzar_hilo(ej_id, urls, modo):
    """Lanza el hilo de analisis para un ej_id dado (conserva el id original).

    Cada nuevo analisis borra los reportes anteriores (archivos en
    reportes/ y uploads/) y descarta las ejecuciones en memoria, para no
    acumular nada. La limpieza corre ANTES de arrancar el hilo nuevo, asi
    que el hilo escribe sus archivos despues y no hay carrera con el.
    """
    _limpiar_reportes_previos()
    ahora = datetime.now()
    with EJECUCIONES_LOCK:
        # Conservar solo la ejecucion actual en memoria.
        EJECUCIONES.clear()
        EJECUCIONES[ej_id] = {
            "id": ej_id, "estado": "ejecutando", "inicio": ahora.strftime("%H:%M:%S"),
            "fecha": ahora.strftime("%Y-%m-%d"),
            "urls": urls, "modo": modo, "total": 0,
            "registros": [], "pdf": None, "txt": None,
            "pdf_error": None, "titulo": (urls[0] if modo == "principal" and len(urls) == 1
                                          else f"{len(urls)} URL(s)"),
            "progreso": 0, "pasos_totales": len(urls),
            "enlaces_preview": [], "dominio_original": "", "confirmado": False,
        }

    def correr():
        def on_progress(hechos, totales):
            with EJECUCIONES_LOCK:
                estado = EJECUCIONES.get(ej_id)
                if estado:
                    estado["progreso"] = hechos
                    estado["pasos_totales"] = totales

        try:
            nombre_reporte = os.path.join(REPORTES_DIR, f"reporte_{ej_id}")
            txt_path = nombre_reporte + ".txt"
            pdf_path = nombre_reporte + ".pdf"

            resultado, rutas = ejecutar_analisis_completo(
                urls, modo=modo, nombre_reporte=nombre_reporte,
                formato="ambos", archivo_txt_path=txt_path,
                on_progress=on_progress,
            )

            with EJECUCIONES_LOCK:
                estado = EJECUCIONES.get(ej_id)
                if estado:
                    estado["estado"] = "completado"
                    estado["registros"] = resultado.get("registros", [])
                    estado["total"] = resultado.get("total", len(urls))
                    estado["pdf"] = rutas.get("pdf")
                    estado["txt"] = rutas.get("txt")
                    estado["pdf_error"] = resultado.get("pdf_error")
                else:
                    # Esta ejecucion fue descartada porque arranco otra
                    # mas reciente: borrar sus reportes para no acumular.
                    for ruta in (rutas.get("pdf"), rutas.get("txt")):
                        try:
                            if ruta and os.path.isfile(ruta):
                                os.unlink(ruta)
                        except OSError:
                            pass
        except Exception as exc:  # pragma: no cover - red
            with EJECUCIONES_LOCK:
                estado = EJECUCIONES.get(ej_id)
                if estado:
                    estado["estado"] = "error"
                    estado["error"] = str(exc)

    hilo = threading.Thread(target=correr, daemon=True)
    hilo.start()


def _lanzar_analisis(urls, modo="lista"):
    ej_id = uuid.uuid4().hex[:12]
    _lanzar_hilo(ej_id, urls, modo)
    flash(f"Analisis iniciado para {len(urls)} URL(s).", "ok")
    return redirect(url_for("resultado", id=ej_id))


@app.route("/preview/<id>")
def preview(id):
    """Muestra la lista de enlaces extraídos (modo principal) antes de analizar."""
    with EJECUCIONES_LOCK:
        ej = dict(EJECUCIONES.get(id, {}))
    if not ej:
        flash("No se encontro ese analisis", "error")
        return redirect(url_for("index"))
    if ej.get("estado") != "preview":
        return redirect(url_for("resultado", id=id))

    return render_template("preview.html",
                           id=id, ej=ej,
                           enlaces=ej.get("enlaces_preview", []),
                           dominio_original=ej.get("dominio_original", ""),
                           tema=CONFIG.get("theme_default", "dark"))


@app.route("/confirmar/<id>", methods=["POST"])
def confirmar(id):
    """Recibe los enlaces seleccionados del preview y lanza el analisis real conservando el id."""
    with EJECUCIONES_LOCK:
        ej = dict(EJECUCIONES.get(id, {}))
    if not ej or ej.get("estado") != "preview":
        flash("No se encontro una vista previa valida", "error")
        return redirect(url_for("index"))

    seleccionados = request.form.getlist("urls")
    if not seleccionados:
        flash("Selecciona al menos un enlace para analizar.", "error")
        return redirect(url_for("preview", id=id))

    modo = ej.get("modo", "principal")
    dominio_original = ej.get("dominio_original", "")

    # Marcar como ejecutando y guardar urls seleccionadas + dominio original
    with EJECUCIONES_LOCK:
        estado = EJECUCIONES.get(id)
        if estado:
            estado["estado"] = "ejecutando"
            estado["confirmado"] = True
            estado["urls"] = seleccionados
            estado["dominio_original"] = dominio_original

    # Lanzar analisis conservando el id original
    _lanzar_hilo(id, seleccionados, modo)

    flash(f"Analisis iniciado para {len(seleccionados)} enlace(s).", "ok")
    return redirect(url_for("resultado", id=id))


@app.route("/estado/<id>")
def estado(id):
    """Endpoint AJAX para consultar el estado de un analisis en tiempo real."""
    with EJECUCIONES_LOCK:
        ej = dict(EJECUCIONES.get(id, {}))
    if not ej:
        return jsonify({"ok": False, "estado": "no_encontrado"})
    return jsonify({
        "ok": True,
        "estado": ej.get("estado"),
        "total": ej.get("total", 0),
        "registros": len(ej.get("registros", [])),
        "progreso": ej.get("progreso", 0),
        "pasos_totales": ej.get("pasos_totales", 0),
        "pdf_disponible": bool(ej.get("pdf") and os.path.isfile(ej.get("pdf") or "")),
        "txt_disponible": bool(ej.get("txt") and os.path.isfile(ej.get("txt") or "")),
    })


@app.route("/api/resultado/<id>")
def api_resultado(id):
    """JSON con los resultados completos de un analisis.

    Lo usa la pagina de resultados para pintar resumen, tabla y botones
    de descarga en el DOM sin recargar la pagina.
    """
    with EJECUCIONES_LOCK:
        ej = dict(EJECUCIONES.get(id, {}))
    if not ej:
        return jsonify({"ok": False, "estado": "no_encontrado"}), 404

    registros = ej.get("registros", [])
    filas = []
    for r in registros:
        res = r.get("resumen") or {}
        tiene_datos = r.get("estado") == "ok" and r.get("resumen")
        filas.append({
            "url": r.get("url", ""),
            "nivel": _riesgo(r),
            "motores": (f"{res.get('total_amenazas', 0)} / "
                        f"{res.get('total_motores_analizados', 0)}"
                        if tiene_datos else None),
            "ultimo_analisis": res.get("ultimo_analisis"),
            "tipos": res.get("tipos_detectados") or [],
        })

    from collections import Counter
    conteo = Counter(f["nivel"] for f in filas)
    resumen = {clave: conteo.get(clave, 0) for clave in
               ("LIMPIO", "REVISAR", "RIESGO ALTO", "SIN DATOS")}

    return jsonify({
        "ok": True,
        "estado": ej.get("estado"),
        "progreso": ej.get("progreso", 0),
        "pasos_totales": ej.get("pasos_totales", 0),
        "total": ej.get("total", 0),
        "resumen": resumen,
        "filas": filas,
        "pdf_disponible": bool(ej.get("pdf") and os.path.isfile(ej.get("pdf") or "")),
        "txt_disponible": bool(ej.get("txt") and os.path.isfile(ej.get("txt") or "")),
        "error": ej.get("error"),
    })


@app.route("/resultado/<id>")
def resultado(id):
    with EJECUCIONES_LOCK:
        ej = dict(EJECUCIONES.get(id, {}))
    if not ej:
        flash("No se encontro ese analisis", "error")
        return redirect(url_for("index"))

    registros = ej.get("registros", [])
    filas = [(r, _riesgo(r)) for r in registros]

    from collections import Counter
    niveles = [nivel for _, nivel in filas]
    conteo = Counter(niveles)

    resumen = [
        ("LIMPIO", "Limpias", "limpio", conteo.get("LIMPIO", 0)),
        ("REVISAR", "A revisar", "revisar", conteo.get("REVISAR", 0)),
        ("RIESGO ALTO", "Riesgo alto", "riesgo-alto", conteo.get("RIESGO ALTO", 0)),
        ("SIN DATOS", "Sin datos", "sin-datos", conteo.get("SIN DATOS", 0)),
    ]

    pdf_disponible = bool(ej.get("pdf") and os.path.isfile(ej.get("pdf") or ""))
    txt_disponible = bool(ej.get("txt") and os.path.isfile(ej.get("txt") or ""))

    return render_template("resultado.html",
                           id=id, ej=ej, filas=filas, resumen=resumen,
                           conteo=conteo, total=ej.get("total", 0),
                           pdf_disponible=pdf_disponible, txt_disponible=txt_disponible,
                           tema=CONFIG.get("theme_default", "dark"))


@app.route("/descargar/txt/<id>")
def descargar_txt(id):
    with EJECUCIONES_LOCK:
        ej = dict(EJECUCIONES.get(id, {}))
    txt = ej.get("txt")
    if not txt or not os.path.isfile(txt):
        flash("TXT no disponible", "error")
        return redirect(url_for("resultado", id=id))
    return send_file(txt, as_attachment=True,
                     download_name=os.path.basename(txt),
                     mimetype="text/plain")


@app.route("/descargar/pdf/<id>")
def descargar_pdf(id):
    with EJECUCIONES_LOCK:
        ej = dict(EJECUCIONES.get(id, {}))
    pdf = ej.get("pdf")
    if not pdf or not os.path.isfile(pdf):
        flash("PDF no disponible", "error")
        return redirect(url_for("resultado", id=id))
    return send_file(pdf, as_attachment=True,
                     download_name=os.path.basename(pdf),
                     mimetype="application/pdf")


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if request.method == "POST":
        cfg = dict(CONFIG)
        try:
            cfg["port"] = int(request.form.get("port", 5505))
        except ValueError:
            cfg["port"] = 5505
        cfg["theme_default"] = request.form.get("theme", "dark")
        sender = (request.form.get("email_sender") or "").strip()
        recipient = (request.form.get("email_recipient") or "").strip()
        cfg["email"] = {
            "enabled": bool(sender and recipient),
            "sender": sender,
            "app_password": "",
            "recipients": [recipient] if recipient else [],
        }
        try:
            tmp = CONFIG_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
            os.replace(tmp, CONFIG_PATH)
            CONFIG.update(cfg)
            flash("Configuracion guardada.", "ok")
        except OSError as exc:
            flash("No se pudo guardar la configuracion: " + str(exc), "error")
        return redirect(url_for("setup"))
    return render_template("setup.html", tema=CONFIG.get("theme_default", "dark"))


@app.route("/health")
def health():
    return jsonify({"ok": True, "servidor": "xoniweb", "puerto": CONFIG.get("port", 5505)})


# --------------------------------------------------------------------------
# Arranque
# --------------------------------------------------------------------------

def main():
    puerto = int(CONFIG.get("port", 5505))
    host = CONFIG.get("host", "0.0.0.0")
    print(f"XONIWEB - modo web en http://{host}:{puerto}")
    print("Sin login. Reportes TXT y PDF bajo demanda.")
    app.run(host=host, port=puerto, debug=False, threaded=True)


if __name__ == "__main__":
    main()
