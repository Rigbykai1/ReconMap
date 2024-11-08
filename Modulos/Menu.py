from Modulos.Utilidades import error_operacion
from Modulos.Utilidades import limpiar_consola
from Modulos.Utilidades import validar_ip
from Modulos.Utilidades import obtener_gateway
from Modulos.Utilidades import obtener_ip_local
from Modulos.Utilidades import listar_archivos
from Modulos.Utilidades import verificar_directorio
from Modulos.Utilidades import verificar_archivo
from Modulos.Utilidades import leer_contenido_archivo
from Modulos.MapeoRed import mostrar_mapeo
from Modulos.MapeoRed import mapeo_red
from Modulos.VerificacionPuertos import escanear_puertos
from Modulos.AsociarPuertosPIDS import listar_puertos_y_pids
from Modulos.PuertosVulnerables import leer_puertos_de_archivo
from Modulos.ListaBlanca import crear_actualizar_whitelist


def mostrar_opciones():

    limpiar_consola()
    print("--- Herramienta de reconocimiento ReconMap --- \n")
    print("1. Verificación de puertos")
    print("2. Mapeo de red")
    print("3. Asociar puertos a programas")
    print("4. Puertos vulnerables")
    print("5. Lista blanca")
    print("6. Salir")


def seleccionar_opcion(opcion):

    directorio = "resultados"
    verificar_directorio(directorio)

    if opcion == '1':
        opcion_verificacion_puertos(directorio)

    elif opcion == '2':
        opcion_mapeo_red()

    elif opcion == '3':
        opcion_asociar_puertos_programas()

    elif opcion == '4':
        opcion_puertos_vulnerables(directorio)

    elif opcion == '5':
        opcion_lista_blanca(directorio)

    elif opcion == '6':
        print("Saliendo...")
        exit()

    else:
        error_operacion(
            "Opción no válida. Por favor, selecciona una opción del menú.")


def opcion_verificacion_puertos(directorio):

    limpiar_consola()
    print("Escribe [ 1 ] si quieres escanear tu dispositivo.")
    print(
        "Escribe [ 2 ] para mostrar la lista de los dispositivos conectados de un archivo de texto.")
    host = input("Introduce la IP o una opción: ")

    if host == "1":
        host = obtener_ip_local()

    if host == "2":
        limpiar_consola()
        archivoMapeo = listar_archivos("Mapeo", ".txt", directorio)
        mostrar_mapeo(archivoMapeo, directorio)
        host = input("Introduce la IP del host para escanear sus puertos: ")

    if validar_ip(host):
        limpiar_consola()
        escanear_puertos(host)

    else:
        error_operacion(
            "IP no válida. Asegúrate de introducir una dirección IP correcta.")


def opcion_mapeo_red():

    limpiar_consola()
    print("Escribe [ 1 ] si quieres escanear tu red local.")
    opcion_mapeo = input("Selecciona una opción o introduce la IP: ")

    if opcion_mapeo == '1':
        gateway = obtener_gateway()

    else:
        gateway = opcion_mapeo

    if validar_ip(gateway):
        print(f"Gateway encontrado: {gateway}")
        rango = f"{gateway}/24"
        mapeo_red(rango)

    else:
        error_operacion(
            "Rango o IP no válido. Verifica la dirección.")


def opcion_asociar_puertos_programas():

    limpiar_consola()
    listar_puertos_y_pids()


def opcion_puertos_vulnerables(directorio):

    limpiar_consola()
    leer_puertos_de_archivo(directorio)


def opcion_lista_blanca(directorio):

    limpiar_consola()
    archivo ="whitelist.txt"
    
    if verificar_archivo(directorio, archivo):
        print("Escribe [ 1 ] si quieres ver la lista.")
        print("Escribe [ 2 ] para actualizar la lista.")
        opcion = input("Selecciona una opción: ")

        if opcion == "1":

            if archivo:
                contenido = leer_contenido_archivo(archivo, directorio)
                input(contenido)
                
        else:
            crear_actualizar_whitelist(directorio)

def menu():

    while True:

        limpiar_consola()
        mostrar_opciones()
        opcion = input("\nSelecciona una opción: ")
        seleccionar_opcion(opcion)
