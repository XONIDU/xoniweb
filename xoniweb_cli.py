#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XONI-WEB 2026 - Modo CLI
Uso:
    python xoniweb_cli.py <url1> [url2 ...]
    python xoniweb_cli.py --archivo urls.txt
    python xoniweb_cli.py --interactivo
"""

import sys
import os
import argparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from xoniweb_core import (
    ejecutar_analisis_completo, obtener_links, normalizar_links,
    SELENIUM_AVAILABLE, REPORTLAB_AVAILABLE,
)


def leer_urls_desde_archivo(ruta):
    urls = []
    with open(ruta, "r", encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
            if linea and not linea.startswith("#"):
                urls.append(linea)
    return urls


def modo_interactivo():
    print("=== XONI-WEB 2026 - Modo CLI interactivo ===")
    print("Escribe una URL por linea. Linea vacia para terminar.\n")
    urls = []
    while True:
        try:
            url = input("URL > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not url:
            break
        urls.append(url)
    return urls


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="xoniweb-cli",
        description="XONI-WEB 2026 - Analisis de URLs con VirusTotal (sin API key)",
    )
    parser.add_argument("urls", nargs="*", help="URL(s) a analizar")
    parser.add_argument("--archivo", "-f", help="Archivo con una URL por linea")
    parser.add_argument("--interactivo", "-i", action="store_true",
                        help="Modo interactivo (una URL por linea)")
    parser.add_argument("--reporte", "-r", default="reporte_xoniweb",
                        help="Nombre base del reporte (sin extension)")
    parser.add_argument("--formato", choices=["txt", "pdf", "ambos"], default="ambos",
                        help="Formato del reporte")
    parser.add_argument("--correo", "-c", help="Enviar PDF por correo a esta direccion")
    parser.add_argument("--web", "-w", action="store_true",
                        help="Iniciar en modo web (Flask) en lugar de CLI")
    args = parser.parse_args(argv)

    if args.web:
        from xoniweb_web import main as web_main
        web_main()
        return 0

    urls = []
    if args.interactivo:
        urls = modo_interactivo()
    if args.archivo:
        urls.extend(leer_urls_desde_archivo(args.archivo))
    if args.urls:
        urls.extend(args.urls)

    # Quitar duplicados preservando orden
    vistos = set()
    urls_unicas = []
    for u in urls:
        if u not in vistos:
            vistos.add(u)
            urls_unicas.append(u)
    urls = urls_unicas

    if not urls:
        print("No se indico ninguna URL. Usa --help para ver las opciones.")
        return 1

    print(f"XONI-WEB 2026 - CLI")
    print(f"Selenium: {'disponible' if SELENIUM_AVAILABLE else 'NO disponible'}")
    print(f"Reportlab (PDF): {'disponible' if REPORTLAB_AVAILABLE else 'NO disponible'}")
    print(f"URLs a analizar: {len(urls)}\n")

    resultado, rutas = ejecutar_analisis_completo(
        urls, modo="lista", nombre_reporte=args.reporte,
        formato=args.formato, email_destinatario=args.correo,
    )

    print("\n" + "=" * 50)
    print("ANALISIS COMPLETADO")
    print("=" * 50)
    print(f"URLs analizadas: {resultado['total']}")
    for r in resultado["registros"]:
        estado = r["estado"]
        res = r.get("resumen")
        if estado == "ok" and res:
            print(f"  {r['url']} -> {res['total_amenazas']} / {res['total_motores_analizados']} motores")
        else:
            print(f"  {r['url']} -> sin datos ({r.get('motivo') or 'desconocido'})")

    if "txt" in rutas:
        print(f"\nReporte TXT: {rutas['txt']}")
    if "pdf" in rutas:
        print(f"Reporte PDF: {rutas['pdf']}")
    if resultado.get("email_enviado"):
        print(f"Correo enviado: {resultado.get('email_mensaje')}")
    elif args.correo:
        print(f"Correo no enviado: {resultado.get('email_mensaje')}")
    if resultado.get("pdf_error"):
        print(f"Error PDF: {resultado['pdf_error']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())