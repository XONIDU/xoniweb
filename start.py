#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XONI-WEB 2026 - Lanzador Universal de Analisis de URLs
Este script ejecuta xoniweb.py y verifica dependencias
Desarrollado por: Darian Alberto Camacho Salas & Oscar Rodolfo Barragan Perez
#Somos XONINDU
"""

import subprocess
import sys
import os
import platform
import shutil
import importlib.util

# Colores para terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    
    @staticmethod
    def supports_color():
        """Verifica si la terminal soporta colores"""
        if platform.system() == 'Windows':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                return kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except:
                return False
        return True

# Desactivar colores si no hay soporte
if not Colors.supports_color():
    for attr in dir(Colors):
        if not attr.startswith('_') and attr != 'supports_color':
            setattr(Colors, attr, '')

def get_system():
    """Detecta el sistema operativo"""
    return platform.system().lower()

def get_linux_distro():
    """Detecta la distribucion de Linux"""
    if get_system() != 'linux':
        return None
    
    try:
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                if 'ubuntu' in content:
                    return 'ubuntu'
                elif 'debian' in content:
                    return 'debian'
                elif 'fedora' in content:
                    return 'fedora'
                elif 'centos' in content:
                    return 'centos'
                elif 'arch' in content:
                    return 'arch'
                elif 'manjaro' in content:
                    return 'manjaro'
                elif 'mint' in content:
                    return 'mint'
        return 'linux-generico'
    except:
        return 'linux-generico'

def get_python_command():
    """Obtiene el comando Python correcto"""
    if get_system() == 'windows':
        return ['python']
    else:
        try:
            subprocess.run(['python3', '--version'], capture_output=True, check=True)
            return ['python3']
        except:
            return ['python']

def print_banner():
    """Muestra el banner de XONI-WEB"""
    sistema = get_system()
    distro = get_linux_distro()
    
    sistema_texto = {
        'windows': 'WINDOWS',
        'linux': f'LINUX ({distro.upper()})' if distro else 'LINUX',
        'darwin': 'MACOS'
    }.get(sistema, 'DESCONOCIDO')
    
    banner = f"""
{Colors.BLUE}{Colors.BOLD}═══════════════════════════════════════════════════════════
                    XONI-WEB 2026 v2.0                    
              Herramienta de Analisis de URLs            
              Web Scraping + VirusTotal Publico          
                                                          
              Sistema detectado: {sistema_texto}            
                                                          
              Desarrollado por:                            
              Darian Alberto Camacho Salas                 
              Oscar Rodolfo Barragan Perez                 
              FES Cuautitlan - UNAM                        
              #Somos XONINDU
═══════════════════════════════════════════════════════════{Colors.END}
    """
    print(banner)

def check_python():
    """Verifica Python instalado"""
    try:
        cmd = get_python_command() + ['--version']
        subprocess.run(cmd, capture_output=True, check=True)
        return True
    except:
        return False

def check_command(comando):
    """Verifica si un comando existe"""
    return shutil.which(comando) is not None

def check_python_module(module_name):
    """Verifica si un modulo de Python esta instalado"""
    return importlib.util.find_spec(module_name) is not None

def check_pip():
    """Verifica si pip esta instalado"""
    try:
        subprocess.run([sys.executable, '-m', 'pip', '--version'], 
                      capture_output=True, check=True)
        return True
    except:
        return False

def install_pip():
    """Instala pip si no esta disponible"""
    sistema = get_system()
    print(f"{Colors.YELLOW}Instalando pip...{Colors.END}")
    
    if sistema == 'windows':
        # Windows - usar get-pip.py
        try:
            import urllib.request
            urllib.request.urlretrieve('https://bootstrap.pypa.io/get-pip.py', 'get-pip.py')
            subprocess.run([sys.executable, 'get-pip.py'], check=True)
            os.remove('get-pip.py')
            print(f"{Colors.GREEN}Pip instalado correctamente{Colors.END}")
            return True
        except:
            print(f"{Colors.RED}Error instalando pip en Windows{Colors.END}")
            print("Descarga manual desde: https://bootstrap.pypa.io/get-pip.py")
            print("Y ejecuta: python get-pip.py")
            return False
    
    elif sistema == 'linux':
        distro = get_linux_distro()
        try:
            if distro in ['ubuntu', 'debian', 'mint']:
                subprocess.run(['sudo', 'apt', 'update'], check=False)
                subprocess.run(['sudo', 'apt', 'install', '-y', 'python3-pip'], check=True)
            elif distro in ['arch', 'manjaro']:
                subprocess.run(['sudo', 'pacman', '-S', '--noconfirm', 'python-pip'], check=True)
            elif distro in ['fedora']:
                subprocess.run(['sudo', 'dnf', 'install', '-y', 'python3-pip'], check=True)
            else:
                # Intentar con get-pip.py
                import urllib.request
                urllib.request.urlretrieve('https://bootstrap.pypa.io/get-pip.py', 'get-pip.py')
                subprocess.run([sys.executable, 'get-pip.py'], check=True)
                os.remove('get-pip.py')
            print(f"{Colors.GREEN}Pip instalado correctamente{Colors.END}")
            return True
        except:
            print(f"{Colors.RED}Error instalando pip{Colors.END}")
            print("Instala manualmente con el gestor de paquetes de tu distro")
            return False
    
    elif sistema == 'darwin':
        try:
            subprocess.run(['brew', 'install', 'python3'], check=False)
            print(f"{Colors.GREEN}Pip instalado correctamente{Colors.END}")
            return True
        except:
            print(f"{Colors.RED}Error instalando pip en macOS{Colors.END}")
            print("Instala manualmente: brew install python3")
            return False
    
    return False

def check_dependencies():
    """Verifica las dependencias de Python necesarias"""
    print(f"\n{Colors.BOLD}Verificando dependencias de Python...{Colors.END}")
    
    dependencias = [
        ('requests', 'requests', 'Peticiones HTTP', 'requests'),
        ('beautifulsoup4', 'beautifulsoup4', 'Web Scraping', 'bs4'),
        ('selenium', 'selenium', 'Automatizacion Web', 'selenium'),
        ('webdriver-manager', 'webdriver-manager', 'Driver Manager', 'webdriver_manager'),
    ]
    
    faltantes = []
    
    for modulo, paquete, desc, import_name in dependencias:
        if import_name == 'bs4':
            if check_python_module('bs4'):
                print(f"{Colors.GREEN}  - {modulo}: OK{Colors.END}")
            else:
                print(f"{Colors.YELLOW}  - {modulo}: FALTANTE{Colors.END}")
                faltantes.append(paquete)
        elif import_name == 'webdriver_manager':
            if check_python_module('webdriver_manager'):
                print(f"{Colors.GREEN}  - {modulo}: OK{Colors.END}")
            else:
                print(f"{Colors.YELLOW}  - {modulo}: FALTANTE{Colors.END}")
                faltantes.append(paquete)
        else:
            if check_python_module(import_name):
                print(f"{Colors.GREEN}  - {modulo}: OK{Colors.END}")
            else:
                print(f"{Colors.YELLOW}  - {modulo}: FALTANTE{Colors.END}")
                faltantes.append(paquete)
    
    # Verificar dependencias del sistema para Selenium en Linux
    if get_system() == 'linux':
        system_deps = ['chromium', 'chromedriver']
        # Verificar si existe chromium o chrome
        if check_command('chromium') or check_command('google-chrome'):
            print(f"{Colors.GREEN}  - chromium/google-chrome: OK{Colors.END}")
        else:
            print(f"{Colors.YELLOW}  - chromium/google-chrome: FALTANTE (recomendado){Colors.END}")
            faltantes.append('sistema-chromium')
        
        if check_command('chromedriver'):
            print(f"{Colors.GREEN}  - chromedriver: OK{Colors.END}")
        else:
            print(f"{Colors.YELLOW}  - chromedriver: FALTANTE (recomendado){Colors.END}")
            faltantes.append('sistema-chromedriver')
    
    return faltantes

def install_dependencies(faltantes):
    """Instala las dependencias faltantes"""
    if not faltantes:
        return True
    
    print(f"\n{Colors.BOLD}Instalando dependencias faltantes...{Colors.END}")
    
    sistema = get_system()
    distro = get_linux_distro()
    
    # Verificar pip primero
    if not check_pip():
        print(f"{Colors.YELLOW}No se encontro pip. Instalando...{Colors.END}")
        if not install_pip():
            print(f"{Colors.RED}No se pudo instalar pip. Instala manualmente.{Colors.END}")
            return False
    
    # Separar paquetes Python de dependencias del sistema
    python_paquetes = [p for p in faltantes if not p.startswith('sistema-')]
    sistema_paquetes = [p.replace('sistema-', '') for p in faltantes if p.startswith('sistema-')]
    
    # Instalar paquetes Python
    if python_paquetes:
        print(f"Paquetes Python a instalar: {', '.join(python_paquetes)}")
        
        # Construir comando de instalacion
        cmd = [sys.executable, '-m', 'pip', 'install']
        
        # IMPORTANTE: --break-system-packages para Linux
        if sistema == 'linux':
            if distro in ['arch', 'manjaro', 'fedora']:
                cmd.append('--break-system-packages')
                print(f"{Colors.YELLOW}Usando --break-system-packages para {distro}{Colors.END}")
            else:
                respuesta = input(f"{Colors.YELLOW}Usar --break-system-packages? (s/n): {Colors.END}")
                if respuesta.lower() == 's':
                    cmd.append('--break-system-packages')
                else:
                    cmd.append('--user')
        elif sistema == 'darwin':
            cmd.append('--user')
        
        cmd.extend(python_paquetes)
        
        # Intentar instalacion
        try:
            print(f"Ejecutando: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)
            print(f"{Colors.GREEN}Dependencias de Python instaladas correctamente{Colors.END}")
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}Error instalando dependencias: {e}{Colors.END}")
            print(f"\n{Colors.YELLOW}Intentando metodo alternativo...{Colors.END}")
            
            # Segundo intento: solo --user
            try:
                cmd2 = [sys.executable, '-m', 'pip', 'install', '--user'] + python_paquetes
                subprocess.run(cmd2, check=True)
                print(f"{Colors.GREEN}Instaladas con --user{Colors.END}")
            except:
                print(f"{Colors.RED}Fallo la instalacion{Colors.END}")
                print(f"\nInstala manualmente:")
                print(f"  pip install {' '.join(python_paquetes)}")
                if sistema == 'linux':
                    print(f"  O con --break-system-packages:")
                    print(f"  pip install --break-system-packages {' '.join(python_paquetes)}")
                return False
    
    # Instalar dependencias del sistema si faltan
    if sistema_paquetes and sistema == 'linux':
        print(f"\n{Colors.YELLOW}Instalando dependencias del sistema...{Colors.END}")
        install_system_dependencies(sistema_paquetes, distro)
    
    return True

def install_system_dependencies(paquetes, distro):
    """Instala dependencias del sistema en Linux"""
    # Mapeo de nombres de paquetes segun distro
    paquetes_map = {
        'chromium': {
            'ubuntu': 'chromium-browser',
            'debian': 'chromium',
            'mint': 'chromium-browser',
            'arch': 'chromium',
            'manjaro': 'chromium',
            'fedora': 'chromium',
        },
        'chromedriver': {
            'ubuntu': 'chromium-chromedriver',
            'debian': 'chromium-driver',
            'mint': 'chromium-chromedriver',
            'arch': 'chromium',
            'manjaro': 'chromium',
            'fedora': 'chromium-driver',
        }
    }
    
    paquetes_instalar = []
    for p in paquetes:
        if p in paquetes_map and distro in paquetes_map[p]:
            paquetes_instalar.append(paquetes_map[p][distro])
        else:
            paquetes_instalar.append(p)
    
    if distro in ['ubuntu', 'debian', 'mint']:
        try:
            subprocess.run(['sudo', 'apt', 'update'], check=False)
            subprocess.run(['sudo', 'apt', 'install', '-y'] + paquetes_instalar, check=True)
            print(f"{Colors.GREEN}Dependencias del sistema instaladas{Colors.END}")
            return True
        except:
            print(f"{Colors.RED}Error instalando dependencias del sistema{Colors.END}")
            print(f"\nInstala manualmente:")
            print(f"  sudo apt install {' '.join(paquetes_instalar)}")
            return False
    
    elif distro in ['fedora']:
        try:
            subprocess.run(['sudo', 'dnf', 'install', '-y'] + paquetes_instalar, check=True)
            print(f"{Colors.GREEN}Dependencias del sistema instaladas{Colors.END}")
            return True
        except:
            print(f"{Colors.RED}Error instalando dependencias del sistema{Colors.END}")
            print(f"\nInstala manualmente:")
            print(f"  sudo dnf install {' '.join(paquetes_instalar)}")
            return False
    
    elif distro in ['arch', 'manjaro']:
        try:
            subprocess.run(['sudo', 'pacman', '-S', '--noconfirm'] + paquetes_instalar, check=True)
            print(f"{Colors.GREEN}Dependencias del sistema instaladas{Colors.END}")
            return True
        except:
            print(f"{Colors.RED}Error instalando dependencias del sistema{Colors.END}")
            print(f"\nInstala manualmente:")
            print(f"  sudo pacman -S {' '.join(paquetes_instalar)}")
            return False
    
    return False

def mostrar_ayuda():
    """Muestra ayuda de uso"""
    ayuda = f"""
{Colors.BOLD}USO DE XONI-WEB:{Colors.END}

  python start.py

{Colors.BOLD}DESCRIPCION:{Colors.END}

  XONI-WEB es una herramienta que analiza URLs y extrae enlaces
  de sitios web, verificando su seguridad con VirusTotal.

{Colors.BOLD}CARACTERISTICAS:{Colors.END}

  - Extrae todos los enlaces de una pagina web
  - Verifica si las URLs son maliciosas con VirusTotal (sin API Key)
  - Genera reportes en .txt o .pdf (seleccionable)
  - Correccion automatica de URLs (agrega https://)
  - Usa Selenium para renderizar JavaScript

{Colors.BOLD}DEPENDENCIAS:{Colors.END}

  - Python 3.6+
  - requests
  - beautifulsoup4
  - selenium
  - webdriver-manager
  - Chromium/Chrome (para Selenium)

{Colors.BOLD}ADVERTENCIA:{Colors.END}

  Este programa es SOLO para fines educativos.
  No lo uses para actividades malintencionadas.

{Colors.BOLD}CONTROLES:{Colors.END}

  - Para salir: Ctrl+C
    """
    print(ayuda)

def verificar_importaciones():
    """Verifica que todas las importaciones necesarias funcionen"""
    print(f"\n{Colors.BOLD}Verificando importaciones...{Colors.END}")
    
    modulos = [
        ('requests', 'requests'),
        ('bs4', 'BeautifulSoup'),
        ('selenium', 'selenium'),
        ('webdriver_manager', 'webdriver_manager'),
    ]
    
    todos_ok = True
    for modulo, nombre in modulos:
        try:
            if modulo == 'bs4':
                from bs4 import BeautifulSoup
                print(f"{Colors.GREEN}  - {nombre}: OK{Colors.END}")
            elif modulo == 'webdriver_manager':
                from webdriver_manager.chrome import ChromeDriverManager
                print(f"{Colors.GREEN}  - {nombre}: OK{Colors.END}")
            else:
                __import__(modulo)
                print(f"{Colors.GREEN}  - {nombre}: OK{Colors.END}")
        except ImportError:
            print(f"{Colors.RED}  - {nombre}: FALLO{Colors.END}")
            todos_ok = False
    
    return todos_ok

def crear_accesos_directos():
    """Crea accesos directos para cada sistema"""
    sistema = get_system()
    
    if sistema == 'windows':
        with open('INICIAR_XONIWEB.bat', 'w') as f:
            f.write("""@echo off
title XONI-WEB 2026 - Analizador de URLs
color 1F
echo ========================================
echo      XONI-WEB 2026 - Analizador de URLs
echo      Desarrollado por Darian y Oscar
echo      FES Cuautitlan - UNAM
echo ========================================
echo.
python start.py
pause
""")
        print(f"{Colors.GREEN}Creado INICIAR_XONIWEB.bat - Haz doble clic para ejecutar{Colors.END}")
    
    elif sistema == 'linux':
        with open('INICIAR_XONIWEB.sh', 'w') as f:
            f.write("""#!/bin/bash
echo "========================================"
echo "      XONI-WEB 2026 - Analizador de URLs"
echo "      Desarrollado por Darian y Oscar"
echo "      FES Cuautitlan - UNAM"
echo "========================================"
echo ""
python3 start.py
read -p "Presiona Enter para salir"
""")
        os.chmod('INICIAR_XONIWEB.sh', 0o755)
        print(f"{Colors.GREEN}Creado INICIAR_XONIWEB.sh - Ejecuta con: ./INICIAR_XONIWEB.sh{Colors.END}")
    
    elif sistema == 'darwin':
        with open('INICIAR_XONIWEB.command', 'w') as f:
            f.write("""#!/bin/bash
cd "$(dirname "$0")"
echo "========================================"
echo "      XONI-WEB 2026 - Analizador de URLs"
echo "      Desarrollado por Darian y Oscar"
echo "      FES Cuautitlan - UNAM"
echo "========================================"
echo ""
python3 start.py
""")
        os.chmod('INICIAR_XONIWEB.command', 0o755)
        print(f"{Colors.GREEN}Creado INICIAR_XONIWEB.command - Haz doble clic para ejecutar{Colors.END}")

def preguntar_formato_reporte():
    """Pregunta al usuario en que formato quiere el reporte"""
    print(f"\n{Colors.BOLD}Formato del reporte:{Colors.END}")
    print("  [1] TXT (texto plano)")
    print("  [2] PDF (documento)")
    print("  [3] Ambos (TXT + PDF)")
    
    while True:
        opcion = input("Selecciona una opcion (1/2/3): ").strip()
        if opcion == '1':
            return 'txt'
        elif opcion == '2':
            return 'pdf'
        elif opcion == '3':
            return 'ambos'
        else:
            print(f"{Colors.YELLOW}Opcion invalida. Elige 1, 2 o 3.{Colors.END}")

def main():
    """Funcion principal"""
    # Limpiar pantalla
    if get_system() == 'windows':
        os.system('cls')
    else:
        os.system('clear')
    
    # Mostrar banner
    print_banner()
    
    # Verificar si hay argumentos de ayuda
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', '/?']:
        mostrar_ayuda()
        input(f"\n{Colors.YELLOW}Presiona Enter para salir...{Colors.END}")
        return
    
    # Verificar Python
    if not check_python():
        print(f"\n{Colors.RED}Error: Python no esta instalado{Colors.END}")
        print("Instala Python desde: https://www.python.org/downloads/")
        input(f"\n{Colors.YELLOW}Presiona Enter para salir...{Colors.END}")
        return
    
    python_version = subprocess.run(get_python_command() + ['--version'], 
                                   capture_output=True, text=True).stdout.strip()
    print(f"{Colors.BOLD}Python:{Colors.END} {python_version}")
    print(f"{Colors.BOLD}Directorio:{Colors.END} {os.path.dirname(os.path.abspath(__file__))}")
    
    # Verificar dependencias
    faltantes = check_dependencies()
    
    if faltantes:
        print(f"\n{Colors.YELLOW}Faltan dependencias{Colors.END}")
        respuesta = input("Instalar automaticamente? (s/n): ")
        
        if respuesta.lower() == 's':
            install_dependencies(faltantes)
        else:
            print(f"\nPuedes instalarlas manualmente con:")
            print("  pip install requests beautifulsoup4 selenium webdriver-manager")
            if get_system() == 'linux':
                print("  O con --break-system-packages:")
                print("  pip install --break-system-packages requests beautifulsoup4 selenium webdriver-manager")
            print("\nY dependencias del sistema:")
            if get_system() == 'linux':
                print("  sudo apt install chromium-browser chromium-chromedriver  # Ubuntu/Debian")
                print("  sudo pacman -S chromium                                # Arch")
                print("  sudo dnf install chromium chromium-driver             # Fedora")
    
    # Verificar que existe xoniweb.py
    if not os.path.exists('xoniweb.py'):
        print(f"\n{Colors.RED}Error: No se encuentra xoniweb.py{Colors.END}")
        print("Asegurate de que xoniweb.py esta en el mismo directorio")
        print("\nPuedes descargarlo desde:")
        print("  https://github.com/XONIDU/xoniweb")
        input(f"\n{Colors.YELLOW}Presiona Enter para salir...{Colors.END}")
        return
    
    # Verificar que las importaciones funcionan
    print(f"\n{Colors.BOLD}Verificando que todo funcione...{Colors.END}")
    if not verificar_importaciones():
        print(f"\n{Colors.RED}Error: No se pueden importar las librerias necesarias{Colors.END}")
        print("El programa no puede continuar sin estas dependencias")
        respuesta = input("Intentar instalar de nuevo? (s/n): ")
        if respuesta.lower() == 's':
            faltantes = ['requests', 'beautifulsoup4', 'selenium', 'webdriver-manager']
            install_dependencies(faltantes)
            if not verificar_importaciones():
                print(f"\n{Colors.RED}Todavia fallan las importaciones. Instala manualmente.{Colors.END}")
                input(f"\n{Colors.YELLOW}Presiona Enter para salir...{Colors.END}")
                return
        else:
            return
    
    # Preguntar formato de reporte
    formato_reporte = preguntar_formato_reporte()
    
    # Pasar formato a xoniweb.py mediante variable de entorno o argumento
    os.environ['XONIWEB_FORMATO'] = formato_reporte
    
    print(f"\n{Colors.BOLD}Iniciando XONI-WEB...{Colors.END}")
    print(f"{Colors.BOLD}Formato de reporte seleccionado: {formato_reporte.upper()}{Colors.END}")
    print(f"{Colors.BOLD}Para salir en cualquier momento:{Colors.END} Ctrl+C")
    print("-" * 60)
    
    # EJECUTAR xoniweb.py - PARTE IMPORTANTE
    try:
        python_cmd = get_python_command()
        cmd = python_cmd + ['xoniweb.py', formato_reporte]
        print(f"Ejecutando: {' '.join(cmd)}")
        print("-" * 60)
        
        # Ejecutar xoniweb.py
        resultado = subprocess.run(cmd)
        
        if resultado.returncode != 0:
            print(f"\n{Colors.RED}Error: xoniweb.py termino con codigo {resultado.returncode}{Colors.END}")
            
    except FileNotFoundError:
        print(f"\n{Colors.RED}Error: No se encuentra xoniweb.py{Colors.END}")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Programa detenido por el usuario{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Error ejecutando xoniweb.py: {e}{Colors.END}")
    
    print(f"\n{Colors.BLUE}Gracias por usar XONI-WEB 2026{Colors.END}")
    print(f"{Colors.BLUE}Desarrollado por:{Colors.END}")
    print(f"{Colors.BLUE}Darian Alberto Camacho Salas{Colors.END}")
    print(f"{Colors.BLUE}Oscar Rodolfo Barragan Perez{Colors.END}")
    print(f"{Colors.BLUE}FES Cuautitlan - UNAM{Colors.END}")
    print(f"{Colors.BLUE}#Somos XONINDU{Colors.END}")
    
    # Pausa al final (excepto en Windows que ya tiene pausa por el .bat)
    if get_system() != 'windows':
        input(f"\n{Colors.YELLOW}Presiona Enter para salir...{Colors.END}")

if __name__ == '__main__':
    try:
        # Crear accesos directos
        crear_accesos_directos()
        
        # Ejecutar programa principal
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Saliendo...{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Error inesperado: {e}{Colors.END}")
        input(f"\n{Colors.YELLOW}Presiona Enter para salir...{Colors.END}")
