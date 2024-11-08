from Modulos.Utilidades import escaner
from Modulos.Utilidades import guardar_resultados
from Modulos.Utilidades import error_operacion
from Modulos.Utilidades import limpiar_consola
from Modulos.Utilidades import formatear_resultados


def escanear_puertos(host):

    resultados = []

    print("Tipo de escaneo:\n1) Escaneo TCP \n2) Escaneo UDP")

    tipo_de_escaneo = input("\nElija una opción: ")

    tipo = 'TCP' if tipo_de_escaneo == '1' else 'UDP' if tipo_de_escaneo == '2' else None

    limpiar_consola()

    if tipo is None:
        print("Opción no válida. Intente nuevamente.")

    try:
        if tipo == 'TCP':
            argumentos = escaneo_tcp()

        elif tipo == 'UDP':
            argumentos = escaneo_udp()

        limpiar_consola()
        print(f"Iniciando escaneo de puertos {tipo} para {host}...\n")
        escaner.scan(host, arguments=argumentos)
        encabezado = "{:<10} {:<20} {:<15} {:<20}".format(
            "Puerto", "Estado", "Protocolo", "servicio")
        separador = "=" * 60
        resultados.append(encabezado)
        resultados.append(separador)
        protocolo = 'tcp' if tipo == 'TCP' else 'udp'

        for puerto in escaner[host][protocolo]:
            estado = escaner[host][protocolo][puerto]['state']
            servicio = escaner[host][protocolo][puerto]['name']
            resultado = f"{puerto:<10} {estado:<20} {tipo:<15} {servicio:<20}"
            resultados.append(resultado)

        formatear_resultados(resultados)
        guardar_resultados(resultados, f"Escaner_{host}_{tipo}.txt")

    except Exception as e:
        error_operacion(f"Error al escanear {host}: {e}")


def escaneo_tcp():

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

    return argumentos


def escaneo_udp():

    print("Selecciona el tipo de escaneo UDP:")
    print("1. Escaneo rápido")
    print("2. Escaneo rápido (top 100 puertos)")
    print("3. Escaneo completo (todos los puertos)")

    opcion_udp = input("\nElige una opción: ")

    if opcion_udp == '1':
        argumentos = '-sU -n'

    elif opcion_udp == '2':
        argumentos = '-sU --top-ports 100'

    elif opcion_udp == '3':
        argumentos = '-sU'

    else:
        print("Opción no válida, se realizará un escaneo rápido por defecto.")
        argumentos = '-sU -n'

    return argumentos
