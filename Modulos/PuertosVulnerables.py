import os
from Modulos.Utilidades import guardar_resultados
from Modulos.Utilidades import error_operacion
from Modulos.Utilidades import formatear_resultados
from Modulos.Utilidades import listar_archivos


def obtener_info_puerto(puerto):
    separador = "-" * 2
    url = f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=port+{
        puerto}&search_type=all&isCpeNameSearch=false"
    info = f"{separador}\nPuerto: {
        puerto}\nInfo del puerto:\n{url}\n{separador}\n"

    return info


def leer_puertos_de_archivo(directorio):

    nombre_archivo = listar_archivos("Escaner", ".txt", directorio)

    if not nombre_archivo:

        return None

    try:
        ruta_archivo = os.path.join(directorio, nombre_archivo)
        resultados = []

        with open(ruta_archivo, 'r') as archivo:
            lineas = archivo.readlines()
            separador = "*" * 80
            titulo = f"\nPuertos vulnerables encontrados en {nombre_archivo}\n"
            cabecera = separador + titulo + separador
            resultados.append(cabecera)

            for linea in lineas[2:]:
                partes = list(filter(None, linea.split()))

                if len(partes) >= 3:
                    puerto = partes[0]
                    estado = partes[1]

                    if estado.lower() in ('open', 'open|filtered'):
                        info_puerto = obtener_info_puerto(puerto)
                        resultados.append(info_puerto)

        formatear_resultados(resultados)
        guardar_resultados(resultados, f'puertos_vulnerables_{
                           nombre_archivo}')

    except FileNotFoundError:
        error_operacion(f"El archivo {nombre_archivo} no se encuentra.")

    except Exception as e:
        error_operacion(f"Se produjo un error: {e}")
