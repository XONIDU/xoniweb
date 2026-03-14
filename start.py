#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XONI-WEB 2026 - Lanzador Universal de Análisis de URLs
Este script ejecuta xoniweb.py y verifica dependencias
Desarrollado por: Darian Alberto Camacho Salas & Oscar Rodolfo Barragán Pérez
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
              Herramienta de Análisis de URLs             
              Web Scraping + VirusTotal API               
                                                          
              Sistema detectado: {sistema_texto}            
                                                          
              Desarrollado por:                            
              Darian Alberto Camacho Salas                 
              Oscar Rodolfo Barragán Pérez                 
              FES Cuautitlán - UNAM                        
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

def check_dependencies():
    """Verifica las dependencias de Python necesarias"""
    print(f"\n{Colors.BOLD}Verificando dependencias de Python...{Colors.END}")
    
    dependencias = [
        ('requests', 'requests', 'Peticiones HTTP', 'requests'),
        ('beautifulsoup4', 'beautifulsoup4', 'Web Scraping', 'bs4'),
    ]
    
    faltantes = []
    
    for modulo, paquete, desc, import_name in dependencias:
        # Para beautifulsoup4 necesitamos verificar bs4
        if import_name == 'bs4':
            if check_python_module('bs4'):
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
    
    return faltantes

def install_dependencies(faltantes):
    """Instala las dependencias faltantes"""
    if not faltantes:
        return True
    
    print(f"\n{Colors.BOLD}Instalando dependencias faltantes...{Colors.END}")
    
    sistema = get_system()
    distro = get_linux_distro()
    
    if faltantes:
        print(f"Paquetes Python a instalar: {', '.join(faltantes)}")
        
        # Construir comando de instalacion
        cmd = [sys.executable, '-m', 'pip', 'install']
        
        # IMPORTANTE: --break-system-packages para Linux
        if sistema == 'linux':
            if distro in ['arch', 'manjaro', 'fedora']:
                cmd.append('--break-system-packages')
                print(f"{Colors.YELLOW}Usando --break-system-packages para {distro}{Colors.END}")
            else:
                # Para otras distros, usar --user es mas seguro
                respuesta = input(f"{Colors.YELLOW}Usar --break-system-packages? (s/n): {Colors.END}")
                if respuesta.lower() == 's':
                    cmd.append('--break-system-packages')
                else:
                    cmd.append('--user')
        elif sistema == 'darwin':
            cmd.append('--user')
        
        cmd.extend(faltantes)
        
        # Intentar instalacion
        try:
            print(f"Ejecutando: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)
            print(f"{Colors.GREEN}Dependencias instaladas correctamente{Colors.END}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}Error instalando dependencias: {e}{Colors.END}")
            print(f"\n{Colors.YELLOW}Intentando metodo alternativo...{Colors.END}")
            
            # Segundo intento: solo --user
            try:
                cmd2 = [sys.executable, '-m', 'pip', 'install', '--user'] + faltantes
                subprocess.run(cmd2, check=True)
                print(f"{Colors.GREEN}Instaladas con --user{Colors.END}")
                return True
            except:
                print(f"{Colors.RED}Fallo la instalacion{Colors.END}")
                print(f"\nInstala manualmente:")
                print(f"  pip install {' '.join(faltantes)}")
                if sistema == 'linux':
                    print(f"  O con --break-system-packages:")
                    print(f"  pip install --break-system-packages {' '.join(faltantes)}")
                return False
    
    return True

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
  - Verifica si las URLs son maliciosas con VirusTotal
  - Genera reportes .txt con fecha, hora y resultados
  - Correccion automatica de URLs (agrega https://)
  - Solicita API Key de VirusTotal si no existe

{Colors.BOLD}API KEY DE VIRUSTOTAL:{Colors.END}

  Para verificar virus necesitas una API Key:
  1. Registrate gratis en: https://www.virustotal.com/gui/join-us
  2. Copia tu API Key
  3. Al ejecutar, el programa te la pedira y la guardara

  Sin API Key, el programa solo extrae enlaces.

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
    ]
    
    todos_ok = True
    for modulo, nombre in modulos:
        try:
            if modulo == 'bs4':
                from bs4 import BeautifulSoup
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
        # Crear .bat para Windows
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
        # Crear .sh para Linux
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
        # Crear .command para Mac
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
            print("  pip install requests beautifulsoup4")
            if get_system() == 'linux':
                print("  O con --break-system-packages:")
                print("  pip install --break-system-packages requests beautifulsoup4")
    
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
            faltantes = ['requests', 'beautifulsoup4']
            install_dependencies(faltantes)
            if not verificar_importaciones():
                print(f"\n{Colors.RED}Todavia fallan las importaciones. Instala manualmente.{Colors.END}")
                input(f"\n{Colors.YELLOW}Presiona Enter para salir...{Colors.END}")
                return
        else:
            return
    
    print(f"\n{Colors.BOLD}Iniciando XONI-WEB...{Colors.END}")
    print(f"{Colors.BOLD}Para salir en cualquier momento:{Colors.END} Ctrl+C")
    print("-" * 60)
    
    # EJECUTAR xoniweb.py - PARTE IMPORTANTE
    try:
        python_cmd = get_python_command()
        cmd = python_cmd + ['xoniweb.py']
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
    print(f"{Colors.BLUE}Oscar Rodolfo Barragán Pérez{Colors.END}")
    print(f"{Colors.BLUE}FES Cuautitlán - UNAM{Colors.END}")
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
