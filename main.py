import os
import nmap
import re
import psutil
import subprocess
import socket
import platform


escaner = nmap.PortScanner()

def limpiar_consola():
    os.system('cls' if os.name == 'nt' else 'clear')
    
def obtener_ip_local():
    try:
        hostname = socket.gethostname()
        ip_local = socket.gethostbyname(hostname)
        return ip_local
    except socket.gaierror:
        print("No se pudo obtener la dirección IP.")
        return None
    
def error_operacion(text):
    print("-" * 67)
    print(text)
    input("\nParece que hubo un error, presiona cualquier tecla para continuar.\n")

def validar_ip(ip):
    patron_ip = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    patron_rango = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$")
    return patron_ip.match(ip) or patron_rango.match(ip)

def obtener_gateway():
    sistema = platform.system()

    sistema = sistema.lower()
    try:
        if sistema == 'linux':
            resultado = subprocess.check_output("ip route | grep default", shell=True).decode().strip()
            return resultado.split()[2]
        elif sistema == 'windows':
            resultado = subprocess.check_output("route print", shell=True).decode().strip()
            for linea in resultado.splitlines():
                if "0.0.0.0" in linea:
                    return linea.split()[2]
        else:
            error_operacion("Opcion no válida. Debe ser 'Windows' o 'Linux")
            return None
    except Exception as e:
        error_operacion(f"Error al obtener el gateway: {e}")
        return None


def escanear_puertos(host):
    resultados = []

    print("Tipo de escaneo:\n1) Escaneo TCP \n2) Escaneo UDP")
    tipo_de_escaneo = input("\nElija una opción: ")
    tipo = 'TCP' if tipo_de_escaneo == '1' else 'UDP' if tipo_de_escaneo == '2' else None

    if tipo is None:
        print("Opción no válida. Intente nuevamente.")
        return {}

    try:
        # Define los argumentos de escaneo en función del tipo seleccionado
        argumentos = ''
        
        # Escaneo TCP con opciones adicionales
        if tipo == 'TCP':
            print("Selecciona el tipo de escaneo TCP:")
            print("1. Escaneo rápido")
            print("2. Escaneo completo (todos los puertos)")
            print("3. Escaneo profundo (SYN)")
            opcion_tcp = input("\nElige una opción: ")
            
            if opcion_tcp == '1':
                argumentos = '-sS -n'
            elif opcion_tcp == '2':
                argumentos = '-sT'
            elif opcion_tcp == '3':
                argumentos = '-sS'
            else:
                print("Opción no válida, se realizará un escaneo rápido por defecto.")
                argumentos = '-sT --top-ports 100'
        
        elif tipo == 'UDP':
            print("Selecciona el tipo de escaneo UDP:")
            print("1. Escaneo rápido (top 100 puertos)")
            print("2. Escaneo rápido")
            print("3. Escaneo completo (todos los puertos)")
            opcion_udp = input("\nElige una opción: ")
            
            if opcion_udp == '1':
                argumentos = '-sU --top-ports 100'
            elif opcion_udp == '2':
                argumentos = '-sU -n'
            elif opcion_udp == '3':
                argumentos = '-sU'
            else:
                print("Opción no válida, se realizará un escaneo rápido por defecto.")
                argumentos = '-sU -n'

        print(f"Iniciando escaneo de puertos {tipo} para {host}...\n")
        
        escaner.scan(host, arguments=argumentos)
        
        encabezado = "{:<10} {:<20} {}".format("Puerto", "Estado", "Protocolo")      
        separador = "=" * 41
        resultados.append(encabezado)
        resultados.append(separador)

        protocolo = 'tcp' if tipo == 'TCP' else 'udp'
        for puerto in escaner[host][protocolo]:
            estado = escaner[host][protocolo][puerto]['state']
            resultado = f"{puerto:<10} {estado:<20} {tipo}"
            resultados.append(resultado)
        
        for resultado in resultados:
            print(resultado)

        guardar_resultados(resultados, f"Escaner_{host}_{tipo}.txt")
        
        return escaner[host]
    
    except Exception as e:
        error_operacion(f"Error al escanear {host}: {e}")
        return {}


def guardar_resultados(resultados, nombre_archivo, carpeta='resultados'):
    if not os.path.exists(carpeta):
        os.makedirs(carpeta)

    ruta_archivo = os.path.join(carpeta, nombre_archivo)

    respuesta = input("\n¿Desea guardar estos resultados? (s/n): ").strip().lower()
    if respuesta == 's':
        with open(ruta_archivo, 'w') as archivo:
            for resultado in resultados:
                archivo.write(resultado + "\n")
        print(f"Resultados guardados en {ruta_archivo}.")
    else:
        print("Resultados no guardados.")
        input("Presione una tecla para continuar.")


def mapeo_red(rango):
    resultados = []
    print(f"\nEscaneando red {rango} para hosts activos...")
    escaner.scan(hosts=rango, arguments='-sP')
    encabezado = "{:<15} {:<10} {:<25} {:<25}".format("IP", "Estado", "Vendor", "MAC")
    separador = "=" * 70
    print(encabezado)
    print(separador)
    resultados.append(encabezado)
    resultados.append(separador)
    for host in escaner.all_hosts():
        item = escaner[host]
        ip = item['addresses'].get('ipv4', 'Desconocido')
        estado = item['status']['state']
        mac = item['addresses'].get('mac', 'Desconocido')
        vendor = item['vendor'].get(mac, 'Desconocido')
        resultado = f"{ip:<15} {estado:<10} {vendor:<25} {mac:<25}"
        resultados.append(resultado)
        print(resultado)
    
    guardar_resultados(resultados, f"Mapeo_Red_{rango.replace('/','_')}.txt")

def obtener_info_proceso(pid):
    try:
        proceso = psutil.Process(pid)
        return proceso.name(), proceso.status()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        error_operacion("Hubo un error al obtener los datos.")
        return None, None

def imprimir_datos(conn, nombre_proceso, estado):
    ip_address = conn.laddr[0]
    port = conn.laddr[1]
    tipo_protocolo = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP' if conn.type == socket.SOCK_DGRAM else 'Desconocido'
    print(f"{tipo_protocolo:<5} {ip_address:<30} {port:<8} {conn.pid:<6} {nombre_proceso:<30} {estado:<15}")

def listar_puertos_y_pids():
    conexiones = psutil.net_connections(kind='inet')
    resultados = []
    
    tcp_conexiones = []
    udp_conexiones = []

    for conn in conexiones:
        nombre_proceso, estado = obtener_info_proceso(conn.pid)
        if nombre_proceso is not None:
            if conn.type == socket.SOCK_STREAM:
                tcp_conexiones.append((conn, nombre_proceso, estado))
            elif conn.type == socket.SOCK_DGRAM:
                udp_conexiones.append((conn, nombre_proceso, estado))

    encabezado = f"{'Proto':<5} {'IP Address - MAC':<30} {'Port':<8} {'PID':<6} {'Process Name':<30} {'Status':<15}"
    separador = "=" * 91

    print(encabezado)
    print(separador)

    for conn, nombre_proceso, estado in tcp_conexiones + udp_conexiones:
        imprimir_datos(conn, nombre_proceso, estado)
    resultados.append(encabezado)
    resultados.append(separador)
    for conn, nombre_proceso, estado in tcp_conexiones + udp_conexiones:
        ip_address = conn.laddr[0]
        port = conn.laddr[1]
        tipo_protocolo = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP' if conn.type == socket.SOCK_DGRAM else 'Desconocido'
        resultado = f"{tipo_protocolo:<5} {ip_address:<30} {port:<8} {conn.pid:<6} {nombre_proceso:<30} {estado:<15}"
        resultados.append(resultado)
    
    guardar_resultados(resultados, "Puertos y procesos.txt")
    
    
def mostrar_mapeo(directorio):
    gateway = obtener_gateway()
    ruta_archivo = os.path.join(directorio, f"Mapeo_Red_{gateway}_24.txt")
    try:
        with open(ruta_archivo, "r") as dispositivos:
            contenido = dispositivos.read()
        
        print("Contenido del mapeo de red:")
        print(contenido)
        
    except FileNotFoundError:
        error_operacion(f"Parece que no se encontraron archivos que coincidan.")
    except Exception as e:
        error_operacion(f"Ocurrió un error al abrir el archivo: {e}")

        
        
def obtener_info_puerto(puerto):
    separador = "-" * 2
    url = f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=port+{puerto}&search_type=all&isCpeNameSearch=false"
    info = f"{separador}\nPuerto: {puerto}\nInfo del puerto:\n{url}\n{separador}\n"
    return info
    

def leer_puertos_de_archivo(directorio, nombre_archivo):
    ruta_archivo = os.path.join(directorio, nombre_archivo)
    resultados = []
    try:
        with open(ruta_archivo, 'r') as archivo:
            lineas = archivo.readlines()
            separador = "*" * 80
            titulo = f"\nPuertos vulnerables encontrados en {nombre_archivo}\n"
            cabecera = separador + titulo + separador
            resultados.append(cabecera)
            print(cabecera)
            
            for linea in lineas[2:]:
                partes = list(filter(None, linea.split()))
                
                if len(partes) >= 3:
                    puerto = partes[0]
                    estado = partes[1]
                    
                    if estado.lower() in ('open', 'open|filtered'):
                        info_puerto = obtener_info_puerto(puerto)
                        resultados.append(info_puerto)
                        print(info_puerto)

        guardar_resultados(resultados, f'puertos_vulnerables_{nombre_archivo}.txt')
        
    except FileNotFoundError:
        error_operacion(f"El archivo {nombre_archivo} no se encuentra.")
    except Exception as e:
        error_operacion(f"Se produjo un error: {e}")
        
def listar_archivos_escaner(directorio):
    archivos_escaner = [archivo for archivo in os.listdir(directorio) if archivo.startswith("Escaner") and archivo.endswith(".txt")]

    if not archivos_escaner:
        error_operacion("No se encontraron archivos que comiencen con 'Escaner'.")
        return None

    print("Archivos de escaneos:")
    for i, archivo in enumerate(archivos_escaner):
        print(f"{i + 1} - {archivo}")

    try:
        seleccion = int(input("Elige el número del archivo que deseas usar: "))
        if 1 <= seleccion <= len(archivos_escaner):
            return archivos_escaner[seleccion - 1]
        else:
            print("Selección no válida. Intenta de nuevo.")
    except ValueError:
        error_operacion("Por favor, introduce un número válido.")
    
    
def menu():
    directorio = "resultados"
    while True:
        limpiar_consola()
        print("--- Herramienta de reconocimiento --- \n")
        print("1. Verificación de puertos")
        print("2. Mapeo de red")
        print("3. Asociar puertos a programas")
        print("4. Puertos vulnerables")
        print("5. Salir")
        
        opcion = input("\nSelecciona una opción: ")
        if opcion == '1':
            limpiar_consola()
            print("Escribe [ 1 ] si quieres escanear tu dispositivo.")
            print("Escribe [ 2 ] para mostrar la lista de los dispositivos conectados de un archivo de texto.")
            host = input("Introduce la IP o una opción: ")
            
            if host == "1":
                host = obtener_ip_local()
                
            if host == "2":
                mostrar_mapeo(directorio)
                host = input("Introduce la IP: ")
            
            if validar_ip(host):
                escanear_puertos(host)
            else:
                print("IP no válida. Asegúrate de introducir una dirección IP correcta.")
        
        elif opcion == '2':
            limpiar_consola()
            gateway = obtener_gateway()
            if gateway:
                print(f"Gateway encontrado: {gateway}")
                rango = f"{gateway}/24"
                mapeo_red(rango)
            else:
                error_operacion("Rango no válido. Asegúrate de introducir un rango correcto.")
        
        elif opcion == '3':
            limpiar_consola()
            listar_puertos_y_pids()
        
        elif opcion == '4':
            limpiar_consola()
            archivo = listar_archivos_escaner(directorio)
            limpiar_consola()
            leer_puertos_de_archivo(directorio, archivo)
            
        elif opcion == '5':
            print("Saliendo...")
            break
        
        else:
            error_operacion("Opción no válida. Por favor, selecciona una opción del menú.")

# Ejecución del menú
if __name__ == "__main__":
    menu()
