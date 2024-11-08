from Modulos.Utilidades import error_operacion
from Modulos.Utilidades import escaner
from Modulos.Utilidades import guardar_resultados
from Modulos.Utilidades import formatear_resultados
from Modulos.Utilidades import leer_contenido_archivo
from Modulos.Utilidades import limpiar_consola


def mapeo_red(rango):

    resultados = []
    print(f"\nEscaneando red {rango} para hosts activos...")
    escaner.scan(hosts=rango, arguments='-sP')
    encabezado = "{:<20} {:<10} {:<40} {:<25}".format(
        "IP", "Estado", "Vendor", "MAC")
    separador = "=" * 90
    resultados.append(encabezado)
    resultados.append(separador)

    for host in escaner.all_hosts():
        item = escaner[host]
        ip = item['addresses'].get('ipv4', 'Desconocido')
        estado = item['status']['state']
        mac = item['addresses'].get('mac', 'Desconocido')
        vendor = item['vendor'].get(mac, 'Desconocido')
        resultado = f"{ip:<20} {estado:<10} {vendor:<40} {mac:<25}"
        resultados.append(resultado)

    if len(resultados)-2 > 0:
        formatear_resultados(resultados)
        guardar_resultados(resultados, f"Mapeo_Red_{
                           rango.replace('/', '_')}.txt")

    else:
        error_operacion("No hay resultados...")


def mostrar_mapeo(archivo, directorio):

    if not archivo:

        return None

    limpiar_consola()
    mapeo = leer_contenido_archivo(archivo, directorio) 
    print(mapeo)
