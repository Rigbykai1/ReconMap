import nmap
import os
import re
import subprocess
import platform
import socket

escaner = nmap.PortScanner()


def verificar_directorio(carpeta):

    if not os.path.exists(carpeta):
        os.makedirs(carpeta)


def verificar_archivo(directorio, nombre_archivo):

    ruta_archivo = os.path.join(directorio, nombre_archivo)

    if ruta_archivo:

        return ruta_archivo

    else:

        return None


def guardar_resultados(resultados, nombre_archivo, carpeta='resultados'):

    if not os.path.exists(carpeta):
        os.makedirs(carpeta)

    ruta_archivo = os.path.join(carpeta, nombre_archivo)
    respuesta = input(
        "\n¿Desea guardar estos resultados? (s/n): ").strip().lower()

    if respuesta == 's':

        with open(ruta_archivo, 'w') as archivo:

            for resultado in resultados:
                archivo.write(resultado + "\n")
        print(f"Resultados guardados en {ruta_archivo}.")
        input("Presiona cualquier tecla para continuar.")

    else:
        print("Resultados no guardados.")
        input("Presione una tecla para continuar.")


def limpiar_consola():

    os.system('cls' if os.name == 'nt' else 'clear')


def error_operacion(text):

    print("-" * 67)
    print(text)
    input("\nPresiona cualquier tecla para continuar.\n")


def validar_ip(ip):

    patron_ip = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    patron_rango = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$")

    return patron_ip.match(ip) or patron_rango.match(ip)


def obtener_sistema_cliente():

    sistema_operativo = platform.system()

    return sistema_operativo.lower()


def obtener_gateway():

    sistema = obtener_sistema_cliente()

    try:

        if sistema == 'linux':
            resultado = subprocess.check_output(
                "ip route | grep default", shell=True).decode().strip()

            return resultado.split()[2]

        elif sistema == 'windows':
            resultado = subprocess.check_output(
                "route print", shell=True).decode().strip()

            for linea in resultado.splitlines():

                if "0.0.0.0" in linea:

                    return linea.split()[2]

        else:
            error_operacion("Opcion no válida. Debe ser 'Windows' o 'Linux")

            return None

    except Exception as e:
        error_operacion(f"Error al obtener el gateway: {e}")

        return None


def obtener_ip_local():

    try:
        hostname = socket.gethostname()
        ip_local = socket.gethostbyname(hostname)

        return ip_local

    except socket.gaierror:
        print("No se pudo obtener la dirección IP.")

        return None


def formatear_resultados(resultados):

    for resultado in resultados:
        print(resultado)


def listar_archivos(palabraClave, extension, directorio):

    archivoBuscado = [archivo for archivo in os.listdir(
        directorio) if archivo.startswith(palabraClave) and archivo.endswith(extension)]

    if not archivoBuscado:
        error_operacion(
            "No se encontraron archivos que comiencen con " + palabraClave)

        return None

    print("Archivos de escaneos:")

    for i, archivo in enumerate(archivoBuscado):
        print(f"{i + 1} - {archivo}")

    try:
        seleccion = int(input("Elige el número del archivo que deseas usar: "))

        if 1 <= seleccion <= len(archivoBuscado):

            return archivoBuscado[seleccion - 1]

        else:
            print("Selección no válida. Intenta de nuevo.")

    except ValueError:
        error_operacion("Por favor, introduce un número válido.")


def leer_contenido_archivo(archivo, directorio):

    try:
        ruta_archivo = verificar_archivo(directorio, archivo)
        input(ruta_archivo)

        with open(ruta_archivo, 'r') as archivo_abierto:
            lineas = archivo_abierto.read()
            return lineas

    except FileNotFoundError:
        error_operacion(
            f"El archivo {archivo} no se encuentra en el directorio.")

    except Exception as e:
        error_operacion(f"Se produjo un error al leer el archivo: {e}")
