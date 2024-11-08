import os
from Modulos.Utilidades import listar_archivos
from Modulos.Utilidades import verificar_archivo
from Modulos.Utilidades import guardar_resultados
from Modulos.Utilidades import limpiar_consola


def crear_actualizar_whitelist(directorio):

    archivo_resultados = listar_archivos("Mapeo", ".txt", directorio)
    archivo_whitelist = "whitelist.txt"
    ruta_archivo = verificar_archivo(directorio, archivo_resultados)

    whitelist = []
    encabezado = "{:<40} {:<25} {:<25}".format(
        "Vendor", "MAC", "Cliente")
    separador = "=" * 90
    whitelist.append(encabezado)
    whitelist.append(separador)


    with open(ruta_archivo, 'r') as file:
        for index, linea in enumerate(file):
            limpiar_consola()
            # Saltar la primera línea si es el encabezado
            if index == 0:
                continue

            # Divide la línea en columnas por espacios
            partes = linea.strip().split()
            if len(partes) < 4:
                continue  # Ignorar líneas que no tengan el formato esperado

            # Extrae IP, estado y MAC con posiciones fijas
            ip = partes[0]
            estado = partes[1]
            mac = partes[-1]

            # El fabricante es el texto entre el estado y la MAC
            fabricante = ' '.join(partes[2:-1])

            # Mostrar los datos para confirmar la whitelist
            print(f"\nDispositivo encontrado:\nIP: {ip}\nEstado: {estado}\nFabricante: {fabricante}\nMAC: {mac}")

            # Pregunta si el dispositivo debe ser agregado a la whitelist
            agregar = input(
                "¿Deseas agregar este dispositivo a la whitelist? (s/n): ")
            if agregar.lower() == 's':
                # Solicita el nombre del usuario o descripción
                nombre_cliente = input(
                    "Introduce el nombre del cliente: ")
                # Agrega el dispositivo a la lista de whitelist con el nombre de usuario
                resultado = f"{fabricante:<40} {mac:<25} {nombre_cliente:<25}"
                whitelist.append(resultado)

        guardar_resultados(whitelist, archivo_whitelist)
