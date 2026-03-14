# 🌐 XONI-WEB 2026

**Herramienta de Análisis de URLs**  
*Web Scraping + VirusTotal API*

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub](https://img.shields.io/badge/github-XONIDU%2Fxoniweb-orange)](https://github.com/XONIDU/xoniweb)

---

## 📋 DESCRIPCIÓN

**XONI-WEB** es una herramienta de código abierto desarrollada en Python que combina técnicas de **web scraping** con la **API de VirusTotal** para analizar URLs y extraer enlaces de sitios web, verificando su seguridad.

Desarrollado por estudiantes de Ingeniería de la **FES Cuautitlán - UNAM** con fines educativos y de investigación en ciberseguridad.

---

## ✨ CARACTERÍSTICAS

| Característica | Descripción |
|----------------|-------------|
| 🔗 **Extracción de enlaces** | Obtiene todos los enlaces (`<a>`) de una página web |
| 🛡️ **Verificación con VirusTotal** | Consulta la reputación de URLs usando la API oficial |
| 📝 **Generación de reportes** | Crea archivos .txt con fecha, hora y resultados detallados |
| 🔄 **Dos modos de análisis** | URL individual o análisis masivo de todos los enlaces |
| 🔧 **Corrección automática** | Agrega https:// si la URL no tiene protocolo |
| 🔑 **Manejo de API Key** | Solicita y guarda automáticamente tu clave de VirusTotal |
| 🖥️ **Multiplataforma** | Funciona en Windows, Linux y macOS |

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

# 2. Instalar dependencias
# Linux (Arch/Manjaro/Fedora)
pip install --break-system-packages requests beautifulsoup4

# Linux (Ubuntu/Debian) y macOS
pip install --user requests beautifulsoup4

# Windows
pip install requests beautifulsoup4

# 3. Ejecutar
python start.py
# o
python xoniweb.py
```

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
requests==2.31.0      # Peticiones HTTP
beautifulsoup4==4.12.2 # Web scraping
```

---

## 🔑 CONFIGURACIÓN DE API KEY (VirusTotal)

Para usar la verificación de virus necesitas una **API Key de VirusTotal**:

1. Regístrate gratis en: [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
2. Copia tu API Key (la encuentras en tu perfil)
3. Al ejecutar **XONI-WEB** por primera vez, te la solicitará automáticamente
4. La clave se guardará en `key_vt.txt` para futuros usos

> **Sin API Key:** El programa sigue funcionando, pero solo extraerá enlaces sin verificar virus.

---

## 📖 CÓMO USAR

### Paso a paso

1. **Ejecuta el programa:**
   ```bash
   python start.py
   ```

2. **Ingresa el nombre del reporte** (sin extensión):
   ```
   Nombre del Reporte (sin extensión): analisis_google
   ```

3. **Ingresa la URL a analizar** (puede ser con o sin https://):
   ```
   Página web a analizar: google.com
   ```

4. **Elige el modo de análisis:**
   ```
   Analizar solo la URL [0]
   Analizar enlaces de URL [1]
   Opción: 0
   ```

5. **Espera los resultados** y el reporte se guardará automáticamente.

### Ejemplo de ejecución

```bash
$ python start.py

═══════════════════════════════════════════════════════════
                    XONI-WEB 2026 v2.0                    
              Herramienta de Análisis de URLs             
              Web Scraping + VirusTotal API               
                                                          
              Sistema detectado: LINUX (ARCH)             
                                                          
              Desarrollado por:                            
              Darian Alberto Camacho Salas                 
              Oscar Rodolfo Barragán Pérez                 
              FES Cuautitlán - UNAM                        
═══════════════════════════════════════════════════════════

Nombre del Reporte (sin extensión): prueba
Página web a analizar: google.com

Analizar solo la URL [0]
Analizar enlaces de URL [1]
Opción: 0

Fecha: 2026-03-13
Hora: 10:30:45

== Enlaces encontrados ==

Texto: Gmail
Enlace: https://mail.google.com/

== Resultado del análisis de virus ==

Resultados para https://google.com:
  - Maliciosos: 0
  - Sospechosos: 0
  - Limpios: 78
✅ La página está limpia de virus.

✅ Reporte guardado en: prueba.txt
```

---

## 📁 ESTRUCTURA DEL PROYECTO

```
xoniweb/
├── start.py                 # Lanzador principal (verifica dependencias)
├── xoniweb.py               # Programa principal de análisis
├── requisitos.txt           # Lista de dependencias
├── README.md                # Este archivo
├── key_vt.txt               # Tu API Key (se genera automáticamente)
├── INICIAR_XONIWEB.bat      # Acceso directo Windows (se genera solo)
├── INICIAR_XONIWEB.sh       # Acceso directo Linux (se genera solo)
└── INICIAR_XONIWEB.command  # Acceso directo macOS (se genera solo)
```

---

## 🛠️ SOLUCIÓN DE PROBLEMAS

| Problema | Solución |
|----------|----------|
| `No module named 'requests'` | Ejecuta: `pip install requests beautifulsoup4` |
| `--break-system-packages` no funciona | Usa: `pip install --user requests beautifulsoup4` |
| Error 401 (API Key inválida) | Verifica tu API Key en `key_vt.txt` o regístrate en VirusTotal |
| URL no válida | El programa ahora agrega `https://` automáticamente |
| No verifica virus | No tienes API Key o es inválida (solo extrae enlaces) |
| Error de permisos en Linux | Usa: `pip install --user -r requisitos.txt` |

---

## 📊 EJEMPLO DE REPORTE GENERADO

```
== Reporte de análisis para: https://google.com ==

Fecha: 2026-03-13
Hora: 10:30:45

== Enlaces encontrados ==

Texto: Gmail
Enlace: https://mail.google.com/

Texto: Imágenes
Enlace: https://images.google.com/

== Resultado del análisis de virus ==

Resultados para https://google.com:
  - Maliciosos: 0
  - Sospechosos: 0
  - Limpios: 78
  - No detectados: 2
✅ La página está limpia de virus.
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
| **Oscar Rodolfo Barragán Pérez** | Estudiante de Ingeniería en Telecomunicaciones, Sistemas y Electrónica - FES Cuautitlán, UNAM |
| **Institución** | Universidad Nacional Autónoma de México - Facultad de Estudios Superiores Cuautitlán |
| **Proyecto** | XONIDU - Desarrollo de software de código abierto |

---

## 📞 CONTACTO Y SOPORTE

| Medio | Enlace |
|-------|--------|
| 📸 Instagram | [@xonidu](https://instagram.com/xonidu) |
| 📘 Facebook | [xonidu](https://www.facebook.com/profile.php?id=61572209206888) |
| 📧 Email | xonidu@gmail.com |
| 💻 GitHub | [XONIDU/xoniweb](https://github.com/XONIDU/xoniweb) |

---

## 📜 LICENCIA

Este proyecto está bajo una licencia de **código abierto** para uso educativo y académico.

