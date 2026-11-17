#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XONI-WEB 2026 - Instalador de dependencias (multiplataforma)
============================================================
Solo instala las dependencias de Python y del sistema.
No ejecuta ni el modo web ni el modo CLI.

Soporta: Linux (Arch, Debian/Ubuntu, Fedora y derivados), macOS y Windows.

Uso:
    python start.py        # instala dependencias y sale
    python start.py --instalar  # igual, solo instala dependencias

Luego ejecuta manualmente:
    python xoniweb_web.py    # modo web (Flask, puerto 5001)
    python xoniweb_cli.py    # modo CLI (analisis manual de URLs)
"""

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

REQUISITOS_PYTHON = [
    "flask>=3.0",
    "waitress>=3.0",
    "requests",
    "beautifulsoup4",
    "selenium",
    "webdriver-manager",
    "reportlab",
    "qrcode[pil]",
]

# Paquetes del sistema por gestor de paquetes
PAQUETES_PACMAN = ["chromium", "chromedriver"]          # Arch / Manjaro
PAQUETES_APT = ["chromium", "chromedriver"]             # Debian / Ubuntu
PAQUETES_DNF = ["chromium", "chromedriver"]             # Fedora
PAQUETES_BREW = ["chromium"]                            # macOS (chromedriver via brew cask)
PAQUETES_WINGET = []                                    # Windows (el usuario instala Chrome manualmente)


def log(msg):
    print(msg, flush=True)


def detectar_sistema():
    """Devuelve (sistema, distribucion, gestor_paquetes)."""
    sistema = platform.system().lower()
    distribucion = None
    gestor = None

    if sistema == "linux":
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                info = {}
                for linea in f:
                    if "=" in linea:
                        k, v = linea.strip().split("=", 1)
                        info[k] = v.strip('"')
                distribucion = info.get("ID", "").lower()
                like = info.get("ID_LIKE", "").lower()
        except Exception:
            like = ""

        if distribucion in ("arch", "manjaro", "endeavouros") or "arch" in like:
            gestor = "pacman"
        elif distribucion in ("debian", "ubuntu", "linuxmint", "pop") or "debian" in like or "ubuntu" in like:
            gestor = "apt"
        elif distribucion in ("fedora", "rhel", "centos", "rocky", "alma") or "fedora" in like or "rhel" in like:
            gestor = "dnf"
        else:
            gestor = "desconocido"

    elif sistema == "darwin":
        gestor = "brew"

    elif sistema == "windows":
        gestor = "winget"

    return sistema, distribucion, gestor


def paquete_instalado(nombre):
    return shutil.which(nombre) is not None


def ejecutar_comando(cmd, descripcion=""):
    """Ejecuta un comando y devuelve (exito, salida_error)."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return res.returncode == 0, res.stderr
    except Exception as exc:
        return False, str(exc)


def instalar_python_multi(pkg):
    """
    Intenta instalar un paquete Python con pip.
    Prueba sin --break-system-packages, luego con --break-system-packages (Arch/PEP 668),
    y al final sugiere venv si nada funciona.
    """
    log(f"> pip install {pkg}")

    # Intento 1: normal
    res = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", pkg],
                         capture_output=True, text=True)
    if res.returncode == 0:
        return True

    # Intento 2: con --break-system-packages (para Arch/PEP 668)
    res2 = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet",
                           "--break-system-packages", pkg],
                          capture_output=True, text=True)
    if res2.returncode == 0:
        return True

    log(f"  AVISO: no se pudo instalar {pkg}")
    return False


def instalar_requirements_multi(req_path):
    """Instala requirements.txt con estrategias multiplataforma."""
    log(f"> pip install -r {req_path}")

    # Intento 1: normal
    res = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet",
                          "-r", str(req_path)],
                         capture_output=True, text=True)
    if res.returncode == 0:
        return True

    # Intento 2: con --break-system-packages
    res2 = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet",
                           "--break-system-packages", "-r", str(req_path)],
                          capture_output=True, text=True)
    if res2.returncode == 0:
        return True

    log("  AVISO: algunos paquetes no se pudieron instalar desde requirements.txt")
    for line in res.stderr.splitlines()[-8:]:
        log(f"  {line}")
    log("")
    log("  Sugerencia: si usas Arch Linux, crea un entorno virtual:")
    log("    python -m venv venv")
    log("    source venv/bin/activate")
    log("    pip install -r requirements.txt")
    return False


def instalar_paquetes_sistema(sistema, gestor, distribucion):
    """Intenta instalar paquetes del sistema segun el gestor detectado."""
    log("\n=== Paquetes del sistema ===")

    if sistema == "linux" and gestor == "pacman":
        paquetes = PAQUETES_PACMAN
        cmd_instalar = ["sudo", "pacman", "-S", "--needed", "--noconfirm"]
    elif sistema == "linux" and gestor == "apt":
        paquetes = PAQUETES_APT
        cmd_instalar = ["sudo", "apt-get", "update", "-qq"]  # actualizar lista primero
        cmd_instalar2 = ["sudo", "apt-get", "install", "-y"]
    elif sistema == "linux" and gestor == "dnf":
        paquetes = PAQUETES_DNF
        cmd_instalar = ["sudo", "dnf", "install", "-y"]
    elif sistema == "darwin" and gestor == "brew":
        paquetes = PAQUETES_BREW
        cmd_instalar = ["brew", "install"]
    elif sistema == "windows" and gestor == "winget":
        paquetes = PAQUETES_WINGET
        cmd_instalar = ["winget", "install"]
    else:
        log("  Gestor de paquetes no detectado automaticamente.")
        log("  Instala manualmente: chromium y chromedriver")
        return

    for pkg in paquetes:
        if paquete_instalado(pkg.split()[0]):
            log(f"  {pkg}: ya instalado")
            continue

        if gestor == "apt":
            ok, err = ejecutar_comando(cmd_instalar, "apt-get update")
            if not ok:
                log(f"  AVISO: no se pudo actualizar lista de apt: {err.strip()[:120]}")
            ok, err = ejecutar_comando(cmd_instalar2 + [pkg], f"apt-get install {pkg}")
        else:
            ok, err = ejecutar_comando(cmd_instalar + [pkg], f"instalar {pkg}")

        if ok:
            log(f"  {pkg}: instalado")
        else:
            log(f"  AVISO: no se pudo instalar {pkg} automaticamente")
            log(f"         Intenta manualmente: sudo <gestor> install {pkg}")

    # Nota especial para chromedriver en macOS
    if sistema == "darwin":
        log("")
        log("  Nota en macOS: chromedriver se instala con:")
        log("    brew install --cask chromedriver")


def instalar_dependencias():
    sistema, distribucion, gestor = detectar_sistema()

    log("=== Instalando dependencias de XONI-WEB 2026 ===")
    log(f"Sistema detectado: {sistema}" + (f" ({distribucion})" if distribucion else "") +
        f" | Gestor: {gestor or 'desconocido'}\n")

    req = BASE_DIR / "requirements.txt"
    if req.is_file():
        instalar_requirements_multi(req)
    else:
        for pkg in REQUISITOS_PYTHON:
            instalar_python_multi(pkg)

    instalar_paquetes_sistema(sistema, gestor, distribucion)

    log("\nDependencias listas.")
    log("Ejecuta manualmente:")
    log("  python xoniweb_web.py    # modo web (Flask, puerto 5505)")
    log("  python xoniweb_cli.py    # modo CLI (analisis manual de URLs)")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="start.py",
                                     description="Instalador de dependencias XONI-WEB 2026")
    parser.add_argument("--instalar", action="store_true",
                        help="Solo instalar dependencias")
    args = parser.parse_args(argv)

    instalar_dependencias()
    return 0


if __name__ == "__main__":
    sys.exit(main())
