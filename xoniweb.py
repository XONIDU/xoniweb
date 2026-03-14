import requests
from bs4 import BeautifulSoup
import base64
from datetime import datetime

#XONIWEB
#SOMOS XONIDU
#Darian Alberto Camacho Salas

# Color de Texto (rojo por defecto)
def color(text):
    print("\033[1;31m" + text + "\033[0m")

# Obtener API Key desde archivo o solicitarla
def cargar_api_key(ruta="key_vt.txt"):
    try:
        with open(ruta, "r") as f:
            api_key = f.read().strip()
            if api_key:
                return api_key
            else:
                print(f"El archivo '{ruta}' está vacío.")
                return solicitar_api_key(ruta)
    except FileNotFoundError:
        print(f"No se encontró el archivo '{ruta}'.")
        return solicitar_api_key(ruta)

def solicitar_api_key(ruta="key_vt.txt"):
    print("\n" + "="*50)
    print("Se requiere una API Key de VirusTotal para continuar.")
    print("Puedes obtener una gratis en: https://www.virustotal.com/gui/join-us")
    print("="*50)
    
    api_key = input("\nIngresa tu API Key de VirusTotal: ").strip()
    
    if api_key:
        # Guardar la key en el archivo para futuros usos
        try:
            with open(ruta, "w") as f:
                f.write(api_key)
            print(f"API Key guardada en '{ruta}' para futuros usos.")
        except Exception as e:
            print(f"Error al guardar la API Key: {e}")
        
        return api_key
    else:
        print("No se ingresó ninguna API Key. El análisis de virus no funcionará.")
        return None

def obtener_links(url):
    # Asegurar que la URL tenga el esquema
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        print(f"URL corregida a: {url}")
    
    try:
        respuesta = requests.get(url, timeout=10)
        respuesta.raise_for_status()
        soup = BeautifulSoup(respuesta.text, 'html.parser')
        enlaces = [(a.get_text(strip=True), a['href']) for a in soup.find_all('a', href=True)]
        return enlaces
    except requests.RequestException as e:
        return f'Error al acceder a la página: {e}'

def verificar_virus(url, archivo):
    api_key = cargar_api_key()
    if not api_key:
        mensaje = "API Key no disponible. No se pudo verificar virus.\n"
        print(mensaje)
        archivo.write(mensaje)
        return

    # Asegurar que la URL tenga el esquema
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    url_encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    url_virustotal = f"https://www.virustotal.com/api/v3/urls/{url_encoded}"

    headers = {
        "x-apikey": api_key
    }

    try:
        print(f"Verificando VirusTotal para: {url}")
        response = requests.get(url_virustotal, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            mensaje = f"\nResultados para {url}:\n"
            mensaje += f"  - Maliciosos: {stats['malicious']}\n"
            mensaje += f"  - Sospechosos: {stats['suspicious']}\n"
            mensaje += f"  - Limpios: {stats['harmless']}\n"
            mensaje += f"  - No detectados: {stats['undetected']}\n"
            
            if stats['malicious'] > 0:
                mensaje += "¡ADVERTENCIA! La página contiene detecciones maliciosas.\n"
            else:
                mensaje += "La página está limpia de virus.\n"
                
        elif response.status_code == 404:
            # La URL no está en VirusTotal, hay que enviarla primero
            mensaje = f"La URL {url} no está en VirusTotal. Enviando para análisis...\n"
            print(mensaje)
            
            # Enviar URL para análisis
            enviar_url_virustotal(url, api_key, archivo)
            return
        else:
            mensaje = f"Error al verificar virus: Código {response.status_code}\n"
            if response.status_code == 401:
                mensaje += "API Key inválida. Por favor verifica tu clave.\n"
                
    except requests.RequestException as e:
        mensaje = f'Error al verificar virus: {e}\n'

    print(mensaje)
    archivo.write(mensaje + "\n")

def enviar_url_virustotal(url, api_key, archivo):
    """Envía una URL a VirusTotal para análisis"""
    url_vt = "https://www.virustotal.com/api/v3/urls"
    
    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    data = {"url": url}
    
    try:
        response = requests.post(url_vt, headers=headers, data=data, timeout=10)
        
        if response.status_code == 200:
            mensaje = f"URL {url} enviada exitosamente a VirusTotal para análisis.\n"
            mensaje += "Espera unos minutos y vuelve a intentar el análisis.\n"
        else:
            mensaje = f"Error al enviar URL: {response.status_code}\n"
    except requests.RequestException as e:
        mensaje = f'Error al enviar URL: {e}\n'
    
    print(mensaje)
    archivo.write(mensaje)

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
        
        nombre_reporte = input("\n Nombre del Reporte (sin extensión): ")
        if not nombre_reporte:
            print("Nombre de reporte inválido.")
            continue
            
        url = input(" Página web a analizar: ").strip()
        if not url:
            print("URL inválida.")
            continue
            
        opcion = input("""\nAnalizar solo la URL [0]
Analizar enlaces de URL [1]
Opción: """)

        filename = f"{nombre_reporte}.txt"
        with open(filename, 'w', encoding='utf-8') as archivo:
            archivo.write(f"== Reporte de análisis para: {url} ==\n\n")
            ahora = datetime.now()
            fecha = ahora.strftime("%Y-%m-%d")
            hora = ahora.strftime("%H:%M:%S")
            print(f"\nFecha: {fecha}\nHora: {hora}")
            archivo.write(f"Fecha: {fecha}\nHora: {hora}\n\n")

            if opcion == "0":
                analizar(url, archivo)
            elif opcion == "1":
                analizar_all(url, archivo)
            else:
                print("Opción inválida.\n")

        print(f"\nReporte guardado en: {filename}\n")
        
        continuar = input("¿Analizar otra URL? (s/n): ").lower()
        if continuar != 's':
            print("¡Hasta luego!")
            break

if __name__ == "__main__":
    main()
