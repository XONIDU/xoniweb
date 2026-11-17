# -*- coding: utf-8 -*-
"""
XONIWEB - Fuentes confiables y gratuitas SIN APIs ni llaves
============================================================

Motor de analisis alternativo al scraping de VirusTotal. Cada fuente es
independiente: si una falla o no esta disponible, las demas siguen
funcionando y el analisis no se cae.

Fuentes (pocas, confiables, sin pago, sin llaves):
  1. OpenPhish  - lista de URLs de phishing, descarga publica en texto
                  plano (https://openphish.com/feed.txt), sin llave.
  2. Spamhaus DBL - lista de bloqueo por DNS: una consulta DNS al
                  dominio, sin llave ni HTTP.
  3. SURBL       - igual que DBL, otra lista por DNS (multi.surbl.org).
  4. Heuristica local - analisis de la URL misma: IP en vez de dominio,
                  punycode, acortadores, typosquatting, subdominios,
                  palabras tipicas de phishing, edad del dominio (WHOIS).
  5. Fetch HTTP  - peticion con requests (sin navegador): cadena de
                  redirecciones y formularios de contrasena.
  6. VirusTotal  - OPCIONAL, solo si hay un driver de Selenium
                  disponible (en Docker con Chromium). Muestra solo los
                  motores curados de la lista MOTORES_VT_CONFIABLES.

ANALISIS POR NIVELES (segun la edad del dominio)
------------------------------------------------
La edad se saca por RDAP (HTTPS, sin llave). Si RDAP no da fecha, se
usa WHOIS clasico (puerto 43). Si tampoco hay, la edad queda
DESCONOCIDA y se trata como dominio nuevo (a lo seguro, nunca se
asume que es viejo sin evidencia).

  - VIEJO (> 1 ano): bastan las listas. Si nada marca y no hay senales
    raras, sale LIMPIO. El navegador solo entra si algo ya marco.
  - MEDIO (30 dias - 1 ano): listas + heuristica + fetch. El navegador
    entra si alguna fuente marco.
  - NUEVO (< 30 dias): analisis profundo siempre que haya navegador
    (contenido de la pagina: formularios, marcas que no son del
    dominio). Ademas la edad misma suma 1 punto sospechoso: un dominio
    nuevo nunca sale LIMPIO solo por no estar en las listas; como mucho
    queda en REVISAR.
  - DESCONOCIDO (no se pudo medir la edad): dispara el analisis
    profundo, pero no suma punto automatico: no se castiga lo que no se
    pudo medir.

Cada fuente que marca la URL suma 1 a "total_amenazas". El veredicto
(LIMPIO / REVISAR / RIESGO ALTO) lo calcula _riesgo() en xoniweb_web.py
con la misma logica de siempre, asi que la interfaz no cambia.

El registro devuelto tiene la misma forma que el de
_consulta_virustotal_publico: {"url", "estado", "motivo", "resumen"} con
resumen = {"total_amenazas", "total_motores_analizados",
"ultimo_analisis", "tipos_detectados", "motores_amenaza"} mas
"edad_dominio_dias" y "nivel_analisis" informativos.
"""

import difflib
import os
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Configuracion
# ---------------------------------------------------------------------------

OPENPHISH_URL = "https://openphish.com/feed.txt"
OPENPHISH_CACHE = os.path.join(BASE_DIR, "data", "openphish.txt")
OPENPHISH_MAX_EDAD_SEG = 3600  # re-descargar la lista cada hora

# Motores de VirusTotal que se muestran (los confiables). Cualquier otro
# motor que marque la URL se ignora en el reporte: pocos, pero confiables.
MOTORES_VT_CONFIABLES = [
    "google safe browsing", "kaspersky", "eset", "fortinet", "sophos",
    "bitdefender", "avira", "mcafee", "microsoft", "symantec", "avast",
    "malwarebytes", "f-secure", "g data", "trendmicro", "avg",
    "phishtank", "sucuri", "forcepoint", "zvelo", "webroot",
]

# Marcas usadas para detectar typosquatting (dominio parecido a la marca).
MARCAS = [
    "google", "facebook", "instagram", "microsoft", "apple", "amazon",
    "netflix", "paypal", "bbva", "banamex", "santander", "hsbc",
    "mercadolibre", "whatsapp", "telegram", "tiktok", "youtube", "gmail",
    "outlook", "hotmail", "liverpool", "coppel", "elektra", "oxxo",
    "telcel", "spotify", "steam", "binance", "coinbase", "banorte",
]

ACORTADORES = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly",
    "shorturl.at", "t.ly", "v.gd", "rb.gy", "s.id", "tiny.cc",
    "soo.gd", "bc.vc", "bitly.is",
}

PALABRAS_SOSPECHOSAS = [
    "login", "verify", "verification", "secure", "security", "update",
    "confirm", "account", "signin", "password", "bank", "free", "bonus",
    "prize", "winner", "urgent", "suspended", "locked", "recover",
    "wallet", "crypto", "invoice", "payment",
]

# Sufijos de dos niveles (para sacar el dominio registrable).
SUFIXOS_DOBLES = {
    "com.mx", "org.mx", "gob.mx", "edu.mx", "co.uk", "org.uk",
    "com.ar", "com.br", "com.co", "com.pe", "com.cl", "com.es",
}

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


# ---------------------------------------------------------------------------
# Utilidades de dominio
# ---------------------------------------------------------------------------

def _dominio_registrable(host):
    """Devuelve el dominio registrable de un host (ej: sub.evil.com -> evil.com)."""
    host = (host or "").lower().strip().rstrip(".")
    partes = host.split(".")
    if len(partes) <= 2:
        return host
    sufijo = ".".join(partes[-2:])
    if sufijo in SUFIXOS_DOBLES and len(partes) >= 3:
        return ".".join(partes[-3:])
    return sufijo


def _es_ip(host):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or ""))


def _normalizar_url(u):
    """Normaliza una URL para compararla con las listas: minusculas, sin
    fragmento, sin barra final, sin query."""
    u = (u or "").strip().lower()
    u = u.split("#")[0].split("?")[0].rstrip("/")
    return u


def _distancia_levenshtein(a, b):
    """Distancia de edicion simple (para typosquatting)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    anterior = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        actual = [i]
        for j, cb in enumerate(b, 1):
            actual.append(min(
                anterior[j] + 1,
                actual[j - 1] + 1,
                anterior[j - 1] + (0 if ca == cb else 1),
            ))
        anterior = actual
    return anterior[-1]


# ---------------------------------------------------------------------------
# Fuente 1: OpenPhish (lista descargable, sin llave)
# ---------------------------------------------------------------------------

def _cargar_openphish():
    """Descarga (con cache de 1 hora) la lista de OpenPhish.

    Devuelve un set de URLs normalizadas, o None si no se pudo obtener
    ni de la red ni del cache.
    """
    try:
        if os.path.isfile(OPENPHISH_CACHE):
            edad = time.time() - os.path.getmtime(OPENPHISH_CACHE)
            if edad < OPENPHISH_MAX_EDAD_SEG:
                with open(OPENPHISH_CACHE, encoding="utf-8", errors="ignore") as f:
                    return {_normalizar_url(l) for l in f if l.strip()}
        resp = requests.get(OPENPHISH_URL, timeout=20,
                            headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        lineas = [l for l in resp.text.splitlines() if l.strip()]
        if not lineas:
            raise ValueError("feed vacio")
        os.makedirs(os.path.dirname(OPENPHISH_CACHE), exist_ok=True)
        with open(OPENPHISH_CACHE, "w", encoding="utf-8") as f:
            f.write("\n".join(lineas))
        return {_normalizar_url(l) for l in lineas}
    except Exception:
        # Sin red: usar el cache aunque este viejo, si existe.
        try:
            if os.path.isfile(OPENPHISH_CACHE):
                with open(OPENPHISH_CACHE, encoding="utf-8", errors="ignore") as f:
                    return {_normalizar_url(l) for l in f if l.strip()}
        except Exception:
            pass
    return None


def _fuente_openphish(url, lista):
    """(corrio, marco, detalle, categoria) para OpenPhish."""
    if lista is None:
        return False, False, None, None
    normal = _normalizar_url(url)
    if normal in lista:
        return True, True, "URL en lista de phishing de OpenPhish", "phishing"
    # Coincidencia por host + ruta (misma pagina, otra query o barra final).
    try:
        p = urlparse(url if "://" in url else "https://" + url)
        host_ruta = _normalizar_url((p.netloc + p.path).lower())
        for entrada in lista:
            e = entrada.replace("http://", "").replace("https://", "")
            if e == host_ruta:
                return True, True, "URL en lista de phishing de OpenPhish", "phishing"
    except Exception:
        pass
    return True, False, None, None


# ---------------------------------------------------------------------------
# Fuentes 2 y 3: DNSBL por DNS (Spamhaus DBL y SURBL, sin llave)
# ---------------------------------------------------------------------------

def _consulta_dnsbl(host, zona, timeout=5):
    """Consulta una lista de bloqueo por DNS.

    Devuelve ("listado", ip) si el host esta listado, ("limpio", None)
    si no lo esta, o ("no_verificado", None) si no se pudo consultar.
    """
    nombre = f"{host}.{zona}"
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            futuro = ex.submit(socket.getaddrinfo, nombre, None)
            resultados = futuro.result(timeout=timeout)
        if not resultados:
            return "limpio", None
        ip = resultados[0][4][0]
        # 127.255.255.254 = el resolver esta bloqueado por Spamhaus:
        # no es un listado, es "no puedo consultar".
        if ip == "127.255.255.254":
            return "no_verificado", None
        if ip.startswith("127.0.0."):
            return "listado", ip
        return "limpio", None
    except Exception:
        return "no_verificado", None


def _fuente_dnsbl(url, zona, nombre):
    """(corrio, marco, detalle, categoria) para una DNSBL."""
    try:
        p = urlparse(url if "://" in url else "https://" + url)
        host = (p.netloc or "").lower().split(":")[0]
        if not host or _es_ip(host):
            return False, False, None, None
        for candidato in {host, _dominio_registrable(host)}:
            estado, _ip = _consulta_dnsbl(candidato, zona)
            if estado == "listado":
                return True, True, f"Dominio listado en {nombre}", "malware"
            if estado == "no_verificado":
                return False, False, None, None
        return True, False, None, None
    except Exception:
        return False, False, None, None


# ---------------------------------------------------------------------------
# Fuente 4: heuristica local (sin servicios externos)
# ---------------------------------------------------------------------------

_CACHE_EDAD = {}


def _edad_dominio_dias(host):
    """Edad del dominio en dias (fecha de registro).

    Primero RDAP por HTTPS (https://rdap.org, sin llave, fecha exacta
    de registro) y si falla, WHOIS clasico (puerto 43). Devuelve None
    si no se puede determinar. Cache en memoria por dominio.
    """
    try:
        if not host or _es_ip(host):
            return None
        if host in _CACHE_EDAD:
            return _CACHE_EDAD[host]
        dias = None
        # 1. RDAP (HTTPS, sin llave): fecha exacta de registro.
        try:
            resp = requests.get(
                "https://rdap.org/domain/" + host, timeout=10,
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
            if resp.status_code == 200:
                datos = resp.json()
                for evento in datos.get("events", []):
                    if evento.get("eventAction") == "registration":
                        fecha_txt = (evento.get("eventDate") or "")[:10]
                        fecha = datetime.strptime(fecha_txt, "%Y-%m-%d")
                        dias = (datetime.utcnow() - fecha).days
                        break
        except Exception:
            dias = None
        # 2. WHOIS clasico (puerto 43) si RDAP no dio fecha.
        if dias is None:
            try:
                if host.endswith((".com", ".net")):
                    servidor = "whois.verisign-grs.com"
                elif host.endswith(".org"):
                    servidor = "whois.pir.org"
                else:
                    servidor = None
                if servidor:
                    sock = socket.create_connection((servidor, 43), timeout=4)
                    try:
                        sock.sendall((host + "\r\n").encode("utf-8", "ignore"))
                        datos = b""
                        sock.settimeout(4)
                        while True:
                            trozo = sock.recv(4096)
                            if not trozo:
                                break
                            datos += trozo
                            if len(datos) > 65536:
                                break
                    finally:
                        sock.close()
                    texto = datos.decode("utf-8", "ignore")
                    m = re.search(r"Creation Date:\s*([0-9T:\-Z ]+)", texto, re.IGNORECASE)
                    if m:
                        fecha_txt = m.group(1).strip().split("T")[0]
                        fecha = datetime.strptime(fecha_txt, "%Y-%m-%d")
                        dias = (datetime.utcnow() - fecha).days
            except Exception:
                dias = None
        _CACHE_EDAD[host] = dias
        return dias
    except Exception:
        return None


def _edad_certificado_dias(host):
    """Edad del certificado TLS en dias (fecha notBefore). Solo es un
    apoyo: un certificado reciente NO prueba que el dominio sea nuevo
    (los certificados se renuevan), pero un certificado muy reciente
    junto a un formulario de login si es una senal. Devuelve None si
    no se puede determinar."""
    try:
        if not host or _es_ip(host):
            return None
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_before = cert.get("notBefore")
        if not not_before:
            return None
        fecha = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        return (datetime.utcnow() - fecha).days
    except Exception:
        return None


# Niveles de analisis segun la edad del dominio (en dias).
EDAD_NUEVO_MAX = 30
EDAD_VIEJO_MIN = 365


def _clasificar_edad(url):
    """Clasifica la edad del dominio de una URL.

    Devuelve (nivel, dias): nivel en {"VIEJO", "MEDIO", "NUEVO",
    "DESCONOCIDO"} y dias es la edad EXACTA (int o None). Si no se
    puede medir, la edad queda DESCONOCIDA: nunca se asume viejo sin
    evidencia.
    """
    try:
        p = urlparse(url if "://" in url else "https://" + url)
        host = (p.netloc or "").lower().split(":")[0]
        registrable = _dominio_registrable(host)
        dias = _edad_dominio_dias(registrable)
    except Exception:
        return "DESCONOCIDO", None
    if dias is not None:
        if dias < EDAD_NUEVO_MAX:
            return "NUEVO", dias
        if dias >= EDAD_VIEJO_MIN:
            return "VIEJO", dias
        return "MEDIO", dias
    return "DESCONOCIDO", None


def _fuente_edad(url, nivel, dias):
    """(corrio, marco, detalle, categoria) para la edad del dominio.

    Solo un dominio NUEVO confirmado suma 1 punto sospechoso por si
    mismo (nunca sale LIMPIO solo por no estar en las listas). Un
    dominio DESCONOCIDO no suma punto: no se castiga lo que no se pudo
    medir; en su lugar dispara el analisis profundo.
    """
    if nivel == "NUEVO":
        return (True, True,
                f"dominio creado hace {dias} dias, sin historial",
                "suspicious")
    return True, False, None, None


def _fuente_heuristica(url, edad_dias=None):
    """(corrio, marco, detalle, categoria) para la heuristica local.

    edad_dias: edad exacta del dominio ya calculada (para no repetir el
    WHOIS). False significa "ya se intento y no se pudo determinar":
    en ese caso no se vuelve a consultar.
    """
    try:
        p = urlparse(url if "://" in url else "https://" + url)
        host = (p.netloc or "").lower().split(":")[0]
        ruta = (p.path or "") + ("?" + p.query if p.query else "")
        texto = (host + ruta).lower()
        registrable = _dominio_registrable(host)
        primera_etiqueta = registrable.split(".")[0]

        razones = []
        peso = 0

        if _es_ip(host):
            razones.append("el host es una IP, no un dominio")
            peso += 2
        if "xn--" in host:
            razones.append("dominio con punycode (caracteres que imitan letras)")
            peso += 1
        if registrable in ACORTADORES:
            razones.append("acortador de URL (oculta el destino real)")
            peso += 1
        if "@" in url:
            razones.append("la URL contiene @ (puede ocultar el dominio real)")
            peso += 1
        if p.scheme == "http":
            razones.append("sin HTTPS")
            peso += 1
        if host.count(".") >= 3 and not _es_ip(host):
            razones.append("demasiados subdominios")
            peso += 1
        if len(url) > 120:
            razones.append("URL inusualmente larga")
            peso += 1

        # Typosquatting: parecido a una marca conocida sin ser ella.
        # Se revisa la primera etiqueta y cada parte separada por guion
        # (ej: "faceb00k-login" contiene "faceb00k", parecido a "facebook").
        tokens = set(primera_etiqueta.replace("_", "-").split("-"))
        tokens.add(primera_etiqueta)
        for marca in MARCAS:
            if primera_etiqueta == marca:
                break
            parecido = any(
                difflib.SequenceMatcher(None, t, marca).ratio() >= 0.85
                or _distancia_levenshtein(t, marca) <= 2
                for t in tokens if t
            )
            if parecido:
                razones.append(f"dominio parecido a la marca '{marca}' (posible typosquatting)")
                peso += 2
                break

        # Palabras tipicas de phishing.
        encontradas = sorted({w for w in PALABRAS_SOSPECHOSAS if w in texto})
        if encontradas:
            razones.append("contiene palabras tipicas de phishing: " + ", ".join(encontradas[:4]))
            peso += 1

        # Dominio recien creado (edad ya calculada por el orquestador).
        if edad_dias is False:
            edad = None  # ya se intento el WHOIS, no repetir
        elif edad_dias is not None:
            edad = edad_dias
        else:
            edad = _edad_dominio_dias(registrable)
        if edad is not None and edad < 30:
            razones.append(f"dominio creado hace {edad} dias")
            peso += 2

        # Certificado TLS muy reciente (apoyo, no prueba de edad: los
        # certificados se renuevan; solo suma si hay otra senal).
        edad_cert = _edad_certificado_dias(host)
        if edad_cert is not None and edad_cert < 7:
            razones.append(f"certificado TLS emitido hace {edad_cert} dias")
            peso += 1

        if peso >= 2:
            return True, True, "; ".join(razones), "suspicious"
        return True, False, None, None
    except Exception:
        return False, False, None, None


# ---------------------------------------------------------------------------
# Fuente 5: fetch HTTP con requests (sin navegador)
# ---------------------------------------------------------------------------

def _fuente_fetch(url, lista_openphish=None):
    """(corrio, marco, detalle, categoria) para el fetch HTTP."""
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": USER_AGENT})
        if resp.status_code >= 400:
            return False, False, None, None
        razones = []
        p_orig = urlparse(url if "://" in url else "https://" + url)
        p_fin = urlparse(resp.url)
        host_orig = (p_orig.netloc or "").lower().split(":")[0]
        host_fin = (p_fin.netloc or "").lower().split(":")[0]
        if host_fin and _dominio_registrable(host_fin) != _dominio_registrable(host_orig):
            # Un acortador redirige por definicion: no es sospechoso.
            # (El destino final igual se revisa contra OpenPhish.)
            # Un cambio a www (mismo dominio) tampoco es sospechoso.
            if _dominio_registrable(host_orig) not in ACORTADORES:
                razones.append(f"redirecciona a otro dominio: {host_fin}")
        # El destino final esta en la lista de phishing.
        if lista_openphish is not None:
            corrio, marco, _d, _c = _fuente_openphish(resp.url, lista_openphish)
            if marco:
                return True, True, "el destino final esta en lista de phishing", "phishing"
        texto = resp.text.lower()
        if 'type="password"' in texto or "type='password'" in texto:
            razones.append("la pagina pide contrasena")
        if razones:
            return True, True, "; ".join(razones), "suspicious"
        return True, False, None, None
    except Exception:
        return False, False, None, None


# ---------------------------------------------------------------------------
# Fuente 6 (opcional): contenido de la pagina con navegador
# ---------------------------------------------------------------------------

def _fuente_contenido_navegador(url, driver):
    """(corrio, marco, detalle, categoria) para el analisis de contenido:
    abre la pagina real con el navegador y revisa que hace.

    Senales: formulario de contrasena, marca mencionada en el titulo o
    texto que no corresponde al dominio (suplantacion). Solo se usa en
    el nivel profundo o cuando otra fuente ya marco.
    """
    try:
        driver.get(url)
        time.sleep(2)
        titulo = (driver.title or "").strip()
        try:
            texto = driver.execute_script(
                "return (document.body ? document.body.innerText : '').slice(0, 3000);"
            ) or ""
        except Exception:
            texto = ""
        try:
            n_pass = driver.execute_script(
                "return document.querySelectorAll('input[type=password]').length;"
            ) or 0
        except Exception:
            n_pass = 0
        p = urlparse(url if "://" in url else "https://" + url)
        host = (p.netloc or "").lower().split(":")[0]
        registrable = _dominio_registrable(host)

        razones = []
        marca_falsa = None
        texto_busqueda = (titulo + " " + texto[:500]).lower()
        for marca in MARCAS:
            if marca in texto_busqueda and marca not in registrable:
                marca_falsa = marca
                break

        if n_pass > 0:
            razones.append("la pagina pide contrasena")
        if marca_falsa:
            razones.append(
                f"la pagina menciona la marca '{marca_falsa}' "
                f"pero el dominio no es {marca_falsa}"
            )
        if not razones:
            return True, False, None, None
        if n_pass > 0 and marca_falsa:
            return True, True, "; ".join(razones), "phishing"
        return True, True, "; ".join(razones), "suspicious"
    except Exception:
        return False, False, None, None


# ---------------------------------------------------------------------------
# Fuente 7 (opcional): VirusTotal por Selenium, solo motores confiables
# ---------------------------------------------------------------------------

def _fuente_virustotal(url, driver, vt_consulta):
    """(corrio, marco, detalle, categoria) para VirusTotal por Selenium."""
    try:
        res = vt_consulta(driver, url)
        if res.get("estado") != "ok" or not res.get("resumen"):
            return False, False, None, None
        resumen = res["resumen"]
        total_vt = resumen.get("total_amenazas", 0)
        total_motores = resumen.get("total_motores_analizados", 0)
        curados = [
            (m, r, c) for (m, r, c) in resumen.get("motores_amenaza", [])
            if any(k in (m or "").lower() for k in MOTORES_VT_CONFIABLES)
        ]
        if not curados:
            return True, False, None, None
        nombres = ", ".join(sorted({m for m, _r, _c in curados})[:5])
        categoria = "suspicious"
        if any(c == "phishing" for _m, _r, c in curados):
            categoria = "phishing"
        elif any(c in ("malware", "malicious") for _m, _r, c in curados):
            categoria = "malware"
        detalle = (
            f"VirusTotal: {total_vt}/{total_motores} motores; "
            f"confiables que lo marcan: {nombres}"
        )
        return True, True, detalle, categoria
    except Exception:
        return False, False, None, None


# ---------------------------------------------------------------------------
# Orquestador: analiza una URL con todas las fuentes disponibles
# ---------------------------------------------------------------------------

def analizar_url_fuentes(url, driver=None, vt_consulta=None):
    """Analiza una URL con las fuentes confiables y gratuitas, por niveles
    segun la edad del dominio.

    Devuelve un registro con la misma forma que _consulta_virustotal_publico,
    asi que el resto de la app (veredicto, reportes, pagina de resultados)
    funciona sin cambios.
    """
    motores_amenaza = []
    tipos = set()
    amenazas = 0
    analizados = 0

    # Nivel segun la edad del dominio (WHOIS; desconocido = como nuevo).
    nivel_edad, dias_edad = _clasificar_edad(url)

    lista_openphish = _cargar_openphish()

    # 0. Edad del dominio: un dominio nuevo o desconocido suma 1 punto
    #    sospechoso por si mismo (nunca sale LIMPIO solo con listas).
    corrio, marco, detalle, categoria = _fuente_edad(url, nivel_edad, dias_edad)
    if corrio:
        analizados += 1
        if marco:
            amenazas += 1
            motores_amenaza.append(("Edad del dominio", detalle, categoria))
            tipos.add(categoria)

    # 1. OpenPhish
    corrio, marco, detalle, categoria = _fuente_openphish(url, lista_openphish)
    if corrio:
        analizados += 1
        if marco:
            amenazas += 1
            motores_amenaza.append(("OpenPhish", detalle, categoria))
            tipos.add(categoria)

    # 2. Spamhaus DBL (por DNS)
    corrio, marco, detalle, categoria = _fuente_dnsbl(url, "dbl.spamhaus.org", "Spamhaus DBL")
    if corrio:
        analizados += 1
        if marco:
            amenazas += 1
            motores_amenaza.append(("Spamhaus DBL", detalle, categoria))
            tipos.add(categoria)

    # 3. SURBL (por DNS)
    corrio, marco, detalle, categoria = _fuente_dnsbl(url, "multi.surbl.org", "SURBL")
    if corrio:
        analizados += 1
        if marco:
            amenazas += 1
            motores_amenaza.append(("SURBL", detalle, categoria))
            tipos.add(categoria)

    # 4. Heuristica local (con la edad ya calculada, sin repetir el WHOIS)
    corrio, marco, detalle, categoria = _fuente_heuristica(
        url, edad_dias=dias_edad if dias_edad is not None else False)
    if corrio:
        analizados += 1
        if marco:
            amenazas += 1
            motores_amenaza.append(("Heuristica local", detalle, categoria))
            tipos.add(categoria)

    # 5. Fetch HTTP
    corrio, marco, detalle, categoria = _fuente_fetch(url, lista_openphish)
    if corrio:
        analizados += 1
        if marco:
            amenazas += 1
            motores_amenaza.append(("Fetch HTTP", detalle, categoria))
            tipos.add(categoria)

    # Nivel de analisis: profundo si el dominio es nuevo/desconocido o si
    # alguna fuente ya marco (escalado). En ese caso se usa el navegador
    # para ver el contenido real de la pagina.
    profundo = nivel_edad in ("NUEVO", "DESCONOCIDO") or amenazas > 0
    if profundo:
        nivel_analisis = "profundo"
    elif nivel_edad == "MEDIO":
        nivel_analisis = "estandar"
    else:
        nivel_analisis = "listas"

    # 6. Contenido con navegador (solo nivel profundo y si hay driver).
    if driver is not None and profundo:
        corrio, marco, detalle, categoria = _fuente_contenido_navegador(url, driver)
        if corrio:
            analizados += 1
            if marco:
                amenazas += 1
                motores_amenaza.append(("Contenido (navegador)", detalle, categoria))
                tipos.add(categoria)

    # 7. VirusTotal por Selenium (solo si hay navegador disponible)
    if driver is not None and vt_consulta is not None:
        corrio, marco, detalle, categoria = _fuente_virustotal(url, driver, vt_consulta)
        if corrio:
            analizados += 1
            if marco:
                amenazas += 1
                motores_amenaza.append(("VirusTotal", detalle, categoria))
                tipos.add(categoria)

    return {
        "url": url,
        "estado": "ok",
        "motivo": None,
        "resumen": {
            "total_amenazas": amenazas,
            "total_motores_analizados": analizados,
            "ultimo_analisis": datetime.now().strftime("%Y-%m-%d %H:%M") + " (local)",
            "tipos_detectados": sorted(tipos),
            "motores_amenaza": motores_amenaza,
            "edad_dominio_dias": dias_edad,
            "nivel_analisis": nivel_analisis,
        },
    }
