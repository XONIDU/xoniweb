import requests
from bs4 import BeautifulSoup
import base64
from datetime import datetime

# Color de Texto (rojo por defecto)
def color(text):
    print("\033[1;31m" + text + "\033[0m")

# Obtener API Key desde archivo
def cargar_api_key(ruta="key_vt.txt"):
    try:
        with open(ruta, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{ruta}' con la API Key.")
        return None

def obtener_links(url):
    try:
        respuesta = requests.get(url)
        respuesta.raise_for_status()
        soup = BeautifulSoup(respuesta.text, 'html.parser')
        enlaces = [(a.get_text(strip=True), a['href']) for a in soup.find_all('a', href=True)]
        return enlaces
    except requests.RequestException as e:
        return f'Error al acceder a la página: {e}'

def verificar_virus(url, archivo):
    api_key = cargar_api_key()
    if not api_key:
        archivo.write("API Key no disponible.\n")
        return

    url_encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    url_virustotal = f"https://www.virustotal.com/api/v3/urls/{url_encoded}"

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url_virustotal, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            if stats['malicious'] > 0:
                mensaje = f"La página {url} contiene virus.\n"
            else:
                mensaje = f"La página {url} está limpia de virus.\n"
        else:
            mensaje = f"Error al verificar virus: {response.status_code}\n"
    except requests.RequestException as e:
        mensaje = f'Error al verificar virus: {e}\n'

    print(mensaje)
    archivo.write(mensaje + "\n")

def analizar(url, archivo):
    links = obtener_links(url)
    if isinstance(links, str):  # Error
        print(links)
        archivo.write(links + "\n")
        return

    archivo.write("== Enlaces encontrados ==\n\n")
    for texto, link in links:
        if link.startswith('/'):
            link = f"{url.rstrip('/')}{link}"
        linea = f'Texto: {texto}\nEnlace: {link}\n\n'
        print(linea)
        archivo.write(linea)

    archivo.write("== Resultado del análisis de virus ==\n\n")
    verificar_virus(url, archivo)

def analizar_all(url, archivo):
    links = obtener_links(url)
    if isinstance(links, str):  # Error
        print(links)
        archivo.write(links + "\n")
        return

    archivo.write("== Análisis completo de enlaces ==\n\n")
    for texto, link in links:
        if link.startswith('/'):
            link = f"{url.rstrip('/')}{link}"
        print(f'Analizando enlace: {link}')
        archivo.write(f'Analizando enlace: {link}\n')
        verificar_virus(link, archivo)
        archivo.write("\n")

def main():
    while True:
        color(""" ~•-|[Xoni-Web]|-•~
    ──▄────▄▄▄▄▄▄▄────▄───
    ─▀▀▄─▄█████████▄─▄▀▀──
    ─────██─▀███▀─██──────
    ───▄─▀████▀████▀─▄────
    ─▀█────██▀█▀██────█▀──
    ───────███████────────

    -By: xonidu""")
        nombre_reporte = input(" Nombre del Reporte (sin extensión): ")
        url = input(" Página web a analizar: ")
        opcion = input("""\nAnalizar solo la URL [0]
Analizar enlaces de URL [1]
Opción: """)

        filename = f"{nombre_reporte}.txt"
        with open(filename, 'w', encoding='utf-8') as archivo:
            archivo.write(f"== Reporte de análisis para: {url} ==\n\n")
            ahora = datetime.now()
            fecha = ahora.strftime("%Y-%m-%d")
            hora = ahora.strftime("%H:%M:%S")
            print("Fecha: ", fecha, "\nHora: ", hora)
            archivo.write(f"Fecha: {fecha}\nHora: {hora}\n\n")

            if opcion == "0":
                analizar(url, archivo)
            elif opcion == "1":
                analizar_all(url, archivo)
            else:
                print("Opción inválida.\n")

        print(f"\nReporte guardado en: {filename}\n")

if __name__ == "__main__":
    main()
