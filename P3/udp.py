'''
    udp.py
    
    Funciones necesarias para implementar el nivel UDP
    
    Autor: Alejandro Raúl Hurtado <alejandror.hurtado@estudiante.uam.es>
    Autor: Camilo Jené Conde <camilo.jenec@estudiante.uam.es>
    2022 EPS-UAM
'''
from ip import *
import struct

UDP_HLEN = 8
UDP_PROTO = 17

def getUDPSourcePort():
    '''
        Nombre: getUDPSourcePort
        Descripción: Esta función obtiene un puerto origen libre en la máquina actual.
        Argumentos:
            -Ninguno
        Retorno: Entero de 16 bits con el número de puerto origen disponible
          
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    portNum =  s.getsockname()[1]
    s.close()
    return portNum

def process_UDP_datagram(us,header,data,srcIP):
    '''
        Nombre: process_UDP_datagram
        Descripción: Esta función procesa un datagrama UDP. Esta función se ejecutará por cada datagrama IP que contenga
        un 17 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer los campos de la cabecera UDP
            -Loggear (usando logging.debug) los siguientes campos:
                -Puerto origen
                -Puerto destino
                -Datos contenidos en el datagrama UDP

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del datagrama UDP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno
          
    '''
    # Extraemos los 4 campos de la cabecera UDP que recibimos en data
    src_port = data[0:2]
    dst_port = data[2:4]
    length = data[4:6]
    checksum = data[6:8]

    # Loggeamos el puerto origen y el destino, seguidos de los datos del datagrama UDP
    logging.debug('Puerto origen: ' + str(src_port))
    logging.debug('Puerto destino: ' + str(dst_port))
    logging.debug('Contenido del datagrama UDP: ' + str(data[8:(struct.unpack('!H', length)[0])]))

    return

def sendUDPDatagram(data,dstPort,dstIP):
    '''
    Nombre: sendUDPDatagram
    Descripción: Esta función construye un datagrama UDP y lo envía
    Esta función debe realizar, al menos, las siguientes tareas:
        -Construir la cabecera UDP:
            -El puerto origen lo obtendremos llamando a getUDPSourcePort
            -El valor de checksum lo pondremos siempre a 0
        -Añadir los datos
        -Enviar el datagrama resultante llamando a sendIPDatagram

    Argumentos:
        -data: array de bytes con los datos a incluir como payload en el datagrama UDP
        -dstPort: entero de 16 bits que indica el número de puerto destino a usar
        -dstIP: entero de 32 bits con la IP destino del datagrama UDP
    Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
        
    '''
    udp_datagram = bytes()
    srcPort = getUDPSourcePort()

    # Construimos el datagrama juntando los datos que obtenemos
    #   - El puerto origen lo obtenemos llamando a getUDPSourcePort
    #   - El puerto destino lo obtenemos como argumento
    #   - La longitud del datagrama es una macro predefinida a 8 sumada a la longitud del argumento data
    #   - El checksum lo ponemos a 0 enviando un byte 0x0000
    #   - El contenido del datagrama es el argumento data
    udp_datagram = struct.pack('!HHHH', srcPort, dstPort, UDP_HLEN + len(data), 0x0000) + data

    # Al llamar a sendIPDatagram enviamos la ip destino que recibimos de argumento, el datagrama que hemos creado
    # y el valor numerico del protocolo UDP que en este caso es una macro definida en 17.
    return sendIPDatagram(dstIP, udp_datagram, UDP_PROTO)


def initUDP():
    '''
        Nombre: initUDP
        Descripción: Esta función inicializa el nivel UDP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_UDP_datagram con el valor de protocolo 17

        Argumentos:
            -Ninguno
        Retorno: Ninguno
          
    '''
    # logging.debug("Inicializando el nivel UDP.")
    registerIPProtocol(process_UDP_datagram, UDP_PROTO)

    return