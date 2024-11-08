import psutil
import socket
from Modulos.Utilidades import guardar_resultados
from Modulos.Utilidades import error_operacion
from Modulos.Utilidades import formatear_resultados


def obtener_info_proceso(pid):

    try:
        proceso = psutil.Process(pid)

        return proceso.name(), proceso.status()

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        error_operacion("Hubo un error al obtener los datos.")

        return None, None


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

    encabezado = f"{'Protocolo':<10} {
        'IPV4 - IPV6':<30} {'Port':<8} {'PID':<6} {'Process Name':<30} {'Status':<15}"
    separador = "=" * 96

    resultados.append(encabezado)
    resultados.append(separador)

    for conn, nombre_proceso, estado in tcp_conexiones + udp_conexiones:
        ip_address = conn.laddr[0]
        port = conn.laddr[1]
        tipo_protocolo = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP' if conn.type == socket.SOCK_DGRAM else 'Desconocido'
        resultado = f"{tipo_protocolo:<10} {ip_address:<30} {
            port:<8} {conn.pid:<6} {nombre_proceso:<30} {estado:<15}"
        resultados.append(resultado)

    formatear_resultados(resultados)
    guardar_resultados(resultados, "Puertos y procesos.txt")
