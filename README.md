# 🌐 XONIWEB 2026

**Herramienta de Análisis de URLs**  
*Web Scraping + VirusTotal API (sin API Key)*

---

## 📋 DESCRIPCIÓN

**XONI-WEB** es una herramienta de código abierto desarrollada en Python que combina técnicas de **web scraping** con **Selenium** para consultar la versión pública de VirusTotal y analizar URLs sin necesidad de API Key.

Desarrollado por estudiantes de Ingeniería de la **FES Cuautitlán - UNAM** con fines educativos y de investigación en ciberseguridad.

---

## ✨ CARACTERÍSTICAS

| Característica | Descripción |
|----------------|-------------|
| Extracción de enlaces | Obtiene todos los enlaces (`<a>`) de una página web |
| Verificación con VirusTotal | Consulta la reputación de URLs usando la versión web pública |
| Generación de reportes | Crea archivos .txt y .pdf con fecha, hora y resultados detallados |
| Dos modos de análisis | URL individual o análisis masivo de todos los enlaces |
| Corrección automática | Agrega https:// si la URL no tiene protocolo |
| Sin API Key | No requiere registro en VirusTotal |
| Multiplataforma | Funciona en Windows, Linux y macOS |

---

## 🚀 INSTALACIÓN RÁPIDA

### Opción 1: Instalación automática (recomendada)

```bash
# 1. Clonar el repositorio
git clone https://github.com/XONIDU/xoniweb.git
cd xoniweb

# 2. Ejecutar el lanzador (instalará dependencias automáticamente)
python start.py
```

### Opción 2: Instalación manual

```bash
# 1. Clonar el repositorio
git clone https://github.com/XONIDU/xoniweb.git
cd xoniweb

# 2. Instalar dependencias Python
# Linux (Arch/Manjaro/Fedora)
pip install --break-system-packages requests beautifulsoup4 selenium webdriver-manager reportlab

# Linux (Ubuntu/Debian) y macOS
pip install --user requests beautifulsoup4 selenium webdriver-manager reportlab

# Windows
pip install requests beautifulsoup4 selenium webdriver-manager reportlab

# 3. Instalar dependencias del sistema
# Linux (Arch/Manjaro)
sudo pacman -S chromium

# Linux (Ubuntu/Debian)
sudo apt install chromium-browser chromium-chromedriver

# Linux (Fedora)
sudo dnf install chromium chromium-driver

# Windows - Descargar Chrome desde: https://www.google.com/chrome/
# macOS - Descargar Chrome desde: https://www.google.com/chrome/

# 4. Ejecutar
python start.py
# o
python xoniweb.py
```

### Opción 3: Usando ejecutables directos (Windows)

En Windows, también puedes usar directamente el archivo `.bat` incluido en el repositorio:

```batch
# 1. Clonar el repositorio
git clone https://github.com/XONIDU/xoniweb.git
cd xoniweb

# 2. Ejecutar directamente (con permisos de administrador)
INICIAR_XONIWEB.bat
```

> **Nota:** El archivo `.bat` solicitará permisos de administrador automáticamente y ejecutará `start.py` con privilegios elevados.

### Opción 4: Comando xoninstall (recomendado para futuras herramientas XONI)

Agrega la siguiente función a tu `~/.bashrc` con un solo comando:

```bash
echo 'xoninstall() { if [ -z "$1" ]; then echo "Uso: xoninstall <repo>"; echo "Ej: xoninstall xoniran"; else git clone "https://github.com/XONIDU/$1.git"; fi; }' >> ~/.bashrc && source ~/.bashrc && echo "Listo. Usa: xoninstall xonicli"
```

Luego simplemente escribe:

```bash
xoninstall xoniweb
cd xoniweb
pip install -r requisitos.txt
python start.py
```

> **Nota:** Esta función te servirá para instalar cualquier otra herramienta futura de XONIDU.

### Opción 5: Instalación desde AUR (Arch Linux)

Si usas Arch Linux, puedes instalar desde el AUR:

```bash
# Usando yay
yay -S xoniweb-git

# Usando paru
paru -S xoniweb-git
```

### Opción 6: Instalación con Docker

```bash
# 1. Clonar el repositorio
git clone https://github.com/XONIDU/xoniweb.git
cd xoniweb

# 2. Construir la imagen Docker
docker build -t xoniweb .

# 3. Ejecutar el contenedor
docker run -it --rm xoniweb
```

### Opción 7: Instalación desde PyPI

```bash
# Instalar desde PyPI
pip install xoniweb

# Ejecutar
xoniweb
```

### Opción 8: Instalación portable (sin instalación)

```bash
# 1. Clonar el repositorio
git clone https://github.com/XONIDU/xoniweb.git
cd xoniweb

# 2. Crear entorno virtual (opcional)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# 3. Instalar dependencias
pip install -r requisitos.txt

# 4. Ejecutar
python xoniweb.py
```

---

### Accesos directos creados automáticamente

Al ejecutar `start.py`, se crearán accesos directos según tu sistema:

| Sistema | Archivo | Cómo usar |
|---------|---------|-----------|
| Windows | `INICIAR_XONIWEB.bat` | Haz doble clic |
| Linux | `INICIAR_XONIWEB.sh` | `./INICIAR_XONIWEB.sh` |
| macOS | `INICIAR_XONIWEB.command` | Haz doble clic |

---

## 📦 DEPENDENCIAS

```
requests==2.31.0           # Peticiones HTTP
beautifulsoup4==4.12.2     # Web scraping
selenium==4.45.0           # Automatización web
webdriver-manager==4.1.2   # Gestor de drivers
reportlab==4.2.5           # Generación de PDF (opcional)
```

### Dependencias del sistema (por plataforma)

| Sistema | Dependencias |
|---------|--------------|
| **Linux (Arch/Manjaro)** | `chromium` |
| **Linux (Ubuntu/Debian)** | `chromium-browser`, `chromium-chromedriver` |
| **Linux (Fedora)** | `chromium`, `chromium-driver` |
| **Windows** | Google Chrome |
| **macOS** | Google Chrome |

---

## 🔑 CONFIGURACIÓN DE API KEY (VirusTotal)

**NUEVO: Este programa ya NO requiere API Key.**

XONI-WEB utiliza la búsqueda web pública de VirusTotal con Selenium para verificar URLs, lo que elimina la necesidad de registrarse y obtener una API Key.

---

## 📖 CÓMO USAR

### Paso a paso

1. **Ejecuta el programa:**
   ```bash
   python start.py
   ```
   *O en Windows directamente con:* `INICIAR_XONIWEB.bat`

2. **Ingresa el nombre del reporte** (sin extensión):
   ```
   Nombre del Reporte (sin extensión): analisis_google
   ```

3. **Ingresa la URL a analizar** (puede ser con o sin https://):
   ```
   Página web a analizar: google.com
   ```

4. **Elige el formato del reporte:**
   ```
   Formato del reporte:
     [1] TXT (texto plano)
     [2] PDF (documento)
     [3] Ambos (TXT + PDF)
   Selecciona una opcion (1/2/3):
   ```

5. **Elige el modo de análisis:**
   ```
   Opciones:
     [0] Analizar solo la URL principal
     [1] Analizar todos los enlaces encontrados
   Opcion: 0
   ```

6. **Espera los resultados** y el reporte se guardará automáticamente.

---

### Ejemplo de ejecución

```bash
$ python start.py

═══════════════════════════════════════════════════════════
                    XONI-WEB 2026 v2.0                    
              Herramienta de Analisis de URLs            
              Web Scraping + VirusTotal Publico          
                                                          
              Sistema detectado: LINUX (ARCH)             
                                                          
              Desarrollado por:                            
              Darian Alberto Camacho Salas                 
              Oscar Rodolfo Barragan Perez                 
              FES Cuautitlan - UNAM                        
              #Somos XONINDU
═══════════════════════════════════════════════════════════

Python: Python 3.14.0
Directorio: /home/albert/xoniweb

Verificando dependencias de Python...
  - requests: OK
  - beautifulsoup4: OK
  - selenium: OK
  - webdriver-manager: OK
  - chromium/google-chrome: OK
  - chromedriver: OK

Verificando importaciones...
  - requests: OK
  - BeautifulSoup: OK
  - selenium: OK
  - webdriver_manager: OK

Formato del reporte:
  [1] TXT (texto plano)
  [2] PDF (documento)
  [3] Ambos (TXT + PDF)
Selecciona una opcion (1/2/3): 3

Iniciando XONI-WEB...
Formato de reporte seleccionado: AMBOS
Para salir en cualquier momento: Ctrl+C

 ╔════════════════════════════════════════════════════════╗
 ║                    XONI-WEB 2026                      ║
 ║              Analisis de URLs sin API Key             ║
 ║          Web Scraping + VirusTotal Publico           ║
 ║                                                      ║
 ║         Desarrollado por: XONIDU - FES UNAM         ║
 ╚════════════════════════════════════════════════════════╝

Nombre del Reporte (sin extension): prueba
Pagina web a analizar: https://www.facebook.com/

Opciones:
  [0] Analizar solo la URL principal
  [1] Analizar todos los enlaces encontrados
Opcion: 0

Fecha: 2026-06-26
Hora: 21:49:16

Enlaces encontrados:
Texto: Registrarte
Enlace: https://www.facebook.com/reg/

[Analisis continuado...]

Reporte TXT guardado en: prueba.txt
Reporte PDF guardado en: prueba.pdf

============================================================
Resumen de archivos generados:
  - prueba.txt
  - prueba.pdf
============================================================

Analizar otra URL? (s/n): n

Hasta luego! - #Somos XONINDU
```

---

## 📁 ESTRUCTURA DEL PROYECTO

```
xoniweb/
├── start.py                 # Lanzador principal (verifica dependencias)
├── xoniweb.py               # Programa principal de análisis
├── requisitos.txt           # Lista de dependencias
├── README.md                # Este archivo
├── key_vt.txt               # (Opcional) API Key (ya no es necesaria)
├── INICIAR_XONIWEB.bat      # Acceso directo Windows (se genera solo)
├── INICIAR_XONIWEB.sh       # Acceso directo Linux (se genera solo)
├── INICIAR_XONIWEB.command  # Acceso directo macOS (se genera solo)
└── debug_vt/                # Carpeta para HTML de depuración
```

---

## 🛠️ SOLUCIÓN DE PROBLEMAS

| Problema | Solución |
|----------|----------|
| `No module named 'requests'` | Ejecuta: `pip install requests beautifulsoup4 selenium webdriver-manager reportlab` |
| `--break-system-packages` no funciona | Usa: `pip install --user requests beautifulsoup4 selenium webdriver-manager reportlab` |
| Selenium no funciona | Instala Chrome/Chromium y el driver correspondiente |
| No verifica virus | Asegúrate que Selenium y Chrome/Chromium estén instalados correctamente |
| Error de permisos en Linux | Usa: `pip install --user -r requisitos.txt` |
| `.bat` no ejecuta en Windows | Ejecuta como administrador (clic derecho > Ejecutar como administrador) |
| ReportLab no instalado | `pip install reportlab` (si no, solo genera TXT) |
| WebDriver no encuentra Chrome | Especifica la ruta: `options.binary_location = '/usr/bin/chromium'` |

---

## 📊 EJEMPLO DE REPORTE GENERADO (TXT)

```
Reporte de analisis para: https://facebook.com
============================================================

Fecha: 2026-06-26
Hora: 21:49:16
============================================================

Enlaces encontrados
==================================================

Texto: Registrarte
Enlace: https://www.facebook.com/reg/

Texto: Iniciar sesion
Enlace: https://www.facebook.com/login/

Resultado del analisis de virus
==================================================

Analizando con Selenium: https://facebook.com
Accediendo a: https://www.virustotal.com/gui/search?query=https%3A%2F%2Ffacebook.com

Resultados para https://facebook.com:
  - Maliciosos: 0
  - Sospechosos: 0
  - Limpios: 78
  - No detectados: 2
La pagina esta limpia de virus.
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

**#Somos XONINDU** 🚀
