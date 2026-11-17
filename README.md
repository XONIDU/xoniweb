# 🌐 XONI-WEB 2026

**Herramienta de Análisis de Reputación de URLs**  
*Web Scraping + VirusTotal Público (sin API Key) — Interfaz Web Flask*

---

## 📋 DESCRIPCIÓN

**XONI-WEB 2026** es una herramienta de código abierto desarrollada en Python que combina técnicas de **web scraping** con **Selenium** para consultar la versión pública de VirusTotal y analizar la reputación de URLs **sin necesidad de API Key**.

La interfaz principal es una aplicación **web Flask** que corre en el puerto **5505**, accesible desde tu computadora o desde el móvil en la misma red (o por Tailscale). Permite pegar listas de URLs, subir archivos (TXT, PDF, Excel), ver una **vista previa de los enlaces extraídos** antes de analizar, priorizar sitios externos, ver una **barra de carga en tiempo real** y descargar reportes en **TXT y PDF**.

Soporta varios usuarios al mismo tiempo sin que los reportes de uno se sobrescriban con los de otro.

---

## ✨ CARACTERÍSTICAS

| Característica | Descripción |
|----------------|-------------|
| Interfaz web profesional | Servidor Flask en puerto 5505, tema oscuro/claro, responsive |
| Análisis sin API Key | Usa la interfaz pública de VirusTotal vía Selenium |
| Extracción de enlaces | Obtiene todos los enlaces (`<a>`) de una página web |
| Vista previa antes de analizar | En modo URL + subenlaces, ves la lista y seleccionas qué analizar |
| Prioridad de sitios externos | Los enlaces de dominios distintos se muestran primero y vienen preseleccionados |
| Barra de carga en tiempo real | Muestra el progreso (X de Y) mientras se analizan las URLs |
| Generación de reportes | Crea archivos .txt y .pdf con fecha, hora y resultados detallados |
| Carga de archivos | Sube TXT, PDF o Excel con listas de URLs |
| Varios usuarios al mismo tiempo | Cada análisis guarda su propio reporte con ID único; no se sobrescriben |
| Modo CLI manual | `python xoniweb_cli.py URL [URL ...]` |
| Descarga móvil | Accesible desde el teléfono en la misma red o por Tailscale |
| Sin API Key | No requiere registro en VirusTotal |
| Multiplataforma | Funciona en Windows, Linux y macOS |

---

## 🚀 INSTALACIÓN RÁPIDA

### Opción 1: Instalación automática (recomendada)

```bash
# 1. Clonar el repositorio
git clone https://github.com/XONIDU/xoniweb.git
cd xoniweb

# 2. Instalar dependencias (Python + sistema)
python start.py --instalar

# 3. Ejecutar el servidor web
python xoniweb_web.py
```

El servidor quedará disponible en: `http://0.0.0.0:5505`  
Desde el móvil (misma red o Tailscale): `http://<IP-de-tu-computadora>:5505`

### Opción 2: Instalación manual

```bash
# 1. Clonar el repositorio
git clone https://github.com/XONIDU/xoniweb.git
cd xoniweb

# 2. Instalar dependencias Python
pip install --break-system-packages -r requirements.txt

# 3. Instalar dependencias del sistema (ejemplo Arch Linux)
sudo pacman -S chromium chromedriver

# 4. Ejecutar el servidor web
python xoniweb_web.py

# 5. (Opcional) Ejecutar modo CLI
python xoniweb_cli.py https://ejemplo.com
```

### Dependencias del sistema (por plataforma)

| Sistema | Dependencias |
|---------|--------------|
| **Linux (Arch/Manjaro)** | `chromium`, `chromedriver` |
| **Linux (Ubuntu/Debian)** | `chromium-browser`, `chromium-chromedriver` |
| **Linux (Fedora)** | `chromium`, `chromium-driver` |
| **macOS** | Google Chrome + `chromedriver` |
| **Windows** | Google Chrome |

---

## 📦 DEPENDENCIAS

**Python** (ver `requirements.txt`):

```
flask>=3.0
waitress>=3.0
requests
beautifulsoup4
selenium
webdriver-manager
reportlab
qrcode[pil]
pypdf          # opcional: extraer URLs de PDF
openpyxl       # opcional: leer URLs de Excel
```

---

## 🔑 CONFIGURACIÓN DE API KEY (VirusTotal)

**Este programa ya NO requiere API Key.**

XONI-WEB utiliza la interfaz pública de VirusTotal a través de Selenium para verificar la reputación de las URLs, lo que elimina la necesidad de registrarse y obtener una API Key.

---

## 📖 CÓMO USAR (WEB)

### Paso a paso

1. **Ejecuta el servidor web:**
   ```bash
   python xoniweb_web.py
   ```

2. **Abre en tu navegador:**
   ```
   http://127.0.0.1:5505
   ```
   Desde el móvil (misma red / Tailscale):
   ```
   http://<IP-de-tu-computadora>:5505
   ```

3. **Ve a "Analizar URLs"**

4. **Pega las URLs** (una por línea) **o sube un archivo** TXT, PDF o Excel con la lista.

5. **Elige el modo de análisis:**
   - **Lista de URLs indicadas**: analiza directamente las URLs que proporcionaste.
   - **URL principal + sus enlaces**: extrae todos los enlaces de la página y te muestra una vista previa para que selecciones cuáles analizar. Los enlaces de sitios externos (dominio distinto) se muestran primero y vienen preseleccionados.

6. **Pulsa "Iniciar análisis"**. Verás una barra de carga que avanza en tiempo real.

7. **Cuando termine**, la página se recarga sola y muestra los resultados. Descarga el reporte en **PDF** o **TXT**.

---

## 📖 CÓMO USAR (CLI)

```bash
# Analizar una o varias URLs
python xoniweb_cli.py https://ejemplo.com https://otra.com

# Analizar URLs desde un archivo
python xoniweb_cli.py --archivo urls.txt

# Modo interactivo (una URL por línea)
python xoniweb_cli.py --interactivo

# Especificar nombre del reporte y formato
python xoniweb_cli.py https://ejemplo.com --reporte mi_analisis --formato ambos

# Enviar el reporte PDF por correo
python xoniweb_cli.py https://ejemplo.com --correo tu@correo.com
```

Opciones del CLI:
- `urls` — una o más URLs a analizar
- `--archivo, -f` — archivo con una URL por línea
- `--interactivo, -i` — modo interactivo
- `--reporte, -r` — nombre base del reporte (sin extensión)
- `--formato` — `txt`, `pdf` o `ambos` (por defecto `ambos`)
- `--correo, -c` — enviar el PDF por correo electrónico

---

## 📁 ESTRUCTURA DEL PROYECTO

```
xoniweb/
├── start.py              # Instalador de dependencias (Python + sistema)
├── xoniweb_web.py        # Aplicación Flask (modo web, puerto 5505)
├── xoniweb_cli.py        # Modo CLI (análisis manual de URLs)
├── xoniweb_core.py       # Lógica de análisis (Selenium, VirusTotal, reportes TXT/PDF)
├── requirements.txt      # Dependencias Python
├── requisitos.txt        # Dependencias adicionales
├── README.md             # Este archivo
├── LICENSE               # Licencia
├── config.json           # Configuración (se crea al guardar)
├── reportes/             # Reportes TXT y PDF generados
├── uploads/              # Archivos subidos temporalmente
├── templates/            # Plantillas HTML
│   ├── base.html
│   ├── index.html
│   ├── analizar.html
│   ├── preview.html      # Vista previa de enlaces antes de analizar
│   ├── resultado.html    # Resultados con barra de carga
│   └── setup.html
└── static/               # CSS y JS
    ├── style.css
    └── app.js
```

---

## ⚠️ ADVERTENCIA LEGAL

**Este programa es únicamente para fines educativos y de investigación.**  
No debe utilizarse para:

- Actividades malintencionadas o ilegales
- Acoso o spam
- Vulnerar sistemas sin autorización
- Cualquier propósito que viole leyes locales o internacionales

El uso indebido es responsabilidad exclusiva del usuario.

---

## 👥 AUTORES

| | |
|---|---|
| **Darian Alberto Camacho Salas** | Estudiante de Ingeniería en Telecomunicaciones, Sistemas y Electrónica - FES Cuautitlán, UNAM |
| **Institución** | Universidad Nacional Autónoma de México - Facultad de Estudios Superiores Cuautitlán |
| **Proyecto** | XONIDU - Desarrollo de software de código abierto |

---

## 📞 CONTACTO Y SOPORTE

| Medio | Enlace |
|-------|--------|
| Instagram | [@xonidu](https://instagram.com/xonidu) |
| Facebook | [xonidu](https://www.facebook.com/profile.php?id=61572209206888) |
| Email | xonidu@gmail.com |
| GitHub | [XONIDU/xoniweb](https://github.com/XONIDU/xoniweb) |

---

## 📜 LICENCIA

Este proyecto está bajo una licencia de **código abierto** para uso educativo y académico.

---

## 🏆 RECONOCIMIENTOS

- **VirusTotal** por su plataforma de análisis
- **FES Cuautitlán - UNAM** por el apoyo académico
- **Comunidad de código abierto** por las herramientas que hacen posible este proyecto

---

**#Somos XONIDU** 🚀