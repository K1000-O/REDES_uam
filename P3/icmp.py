'''
    icmp.py
    
    Funciones necesarias para implementar el nivel ICMP
    
    Autor: Alejandro Raúl Hurtado <alejandror.hurtado@estudiante.uam.es>
    Autor: Camilo Jené Conde <camilo.jenec@estudiante.uam.es>
    2022 EPS-UAM
'''
from ip import *
from threading import Lock
import struct

ICMP_PROTO = 1
ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0

timeLock = Lock()
icmp_send_times = {}

def process_ICMP_message(us,header,data,srcIp):
    '''
        Nombre: process_ICMP_message
        Descripción: Esta función procesa un mensaje ICMP. Esta función se ejecutará por cada datagrama IP que contenga
        un 1 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Calcular el checksum de ICMP y comprobar si es correcto:
            -Extraer campos tipo y código de la cabecera ICMP
            -Loggear (con logging.debug) el valor de tipo y código
            -Si el tipo es ICMP_ECHO_REQUEST_TYPE:
                -Generar un mensaje de tipo ICMP_ECHO_REPLY como respuesta. Este mensaje debe contener
                los datos recibidos en el ECHO_REQUEST. Es decir, "rebotamos" los datos que nos llegan.
                -Enviar el mensaje usando la función sendICMPMessage
            -Si el tipo es ICMP_ECHO_REPLY_TYPE:
                -Extraer del diccionario icmp_send_times el valor de tiempo de envío usando como clave los campos srcIP e icmp_id e icmp_seqnum
                contenidos en el mensaje ICMP. Restar el tiempo de envio extraído con el tiempo de recepción (contenido en la estructura pcap_pkthdr)
                -Se debe proteger el acceso al diccionario de tiempos usando la variable timeLock
                -Mostrar por pantalla la resta. Este valor será una estimación del RTT
            -Si es otro tipo:
                -No hacer nada

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del mensaje ICMP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno
          
    '''
    # Comprobamos si el checksum de data es correcto
    if chksum(data) != 0:
        logging.debug("Cheksum != 0: no válido.")
        #return

    # Extraemos el tipo y el codigo de la cabecera ICMP y los imprimimos con logging debug    
    tipo = data[0]
    logging.debug("Tipo ICMP: " + str(tipo))

    codigo = data[1]
    logging.debug("Codigo ICMP: " + str(codigo))

    # Comprobamos el tipo
    icmp_id = struct.unpack('!H',data[4:6])[0]
    icmp_seq = struct.unpack('!H',data[4:6])[0]

    if tipo == ICMP_ECHO_REQUEST_TYPE:
        sendICMPMessage(data, ICMP_ECHO_REPLY_TYPE, 0, icmp_id, icmp_seq, srcIp)
    elif tipo == ICMP_ECHO_REPLY_TYPE:
        with timeLock:
            t_dict = icmp_send_times[int.from_bytes(srcIp, "big") + icmp_id + icmp_seq]
        
        resta = header.ts.tv_sec - t_dict
        print("Estimación del RTT: " + str(resta))
    
    return
    

def sendICMPMessage(data,type,code,icmp_id,icmp_seqnum,dstIP):
    '''
        Nombre: sendICMPMessage
        Descripción: Esta función construye un mensaje ICMP y lo envía.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Si el campo type es ICMP_ECHO_REQUEST_TYPE o ICMP_ECHO_REPLY_TYPE:
                -Construir la cabecera ICMP
                -Añadir los datos al mensaje ICMP
                -Calcular el checksum y añadirlo al mensaje donde corresponda (OK)
                -Si type es ICMP_ECHO_REQUEST_TYPE
                    -Guardar el tiempo de envío (llamando a time.time()) en el diccionario icmp_send_times
                    usando como clave el valor de dstIp+icmp_id+icmp_seqnum
                    -Se debe proteger al acceso al diccionario usando la variable timeLock

                -Llamar a sendIPDatagram para enviar el mensaje ICMP
                
            -Si no:
                -Tipo no soportado. Se devuelve False

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el mensaje ICMP
            -type: valor del campo tipo de ICMP
            -code: valor del campo code de ICMP 
            -icmp_id: entero que contiene el valor del campo ID de ICMP a enviar
            -icmp_seqnum: entero que contiene el valor del campo Seqnum de ICMP a enviar
            -dstIP: entero de 32 bits con la IP destino del mensaje ICMP
        Retorno: True o False en función de si se ha enviado el mensaje correctamente o no
          
    '''
    icmp_message = bytes()

    if type is not ICMP_ECHO_REQUEST_TYPE and type is not ICMP_ECHO_REPLY_TYPE:
        logging.debug("ERROR: el tipo enviado por ICMP no es soportado.")
        return False

    # Construimos la cabecera ICMP
    header = bytearray()
    header += type.to_bytes(1, "big") + code.to_bytes(1, "big") + b"\x00\x00" \
        + icmp_id.to_bytes(2, "big") + icmp_seqnum.to_bytes(2, "big")

    # Creamos el datagrama con los datos.
    icmp_message = bytes()
    icmp_message += header + data

    # Calculamos el checksum y lo añadimos.
    checksum = chksum(icmp_message)
    header[2:4] = checksum.to_bytes(2, "big")  # Al cambiar el header, como su tipo es bytearray() --> Se modifica el datagram.

    if type is ICMP_ECHO_REQUEST_TYPE:
        with timeLock:
            icmp_send_times[dstIP + icmp_id + icmp_seqnum] = time.time()

    return sendIPDatagram(dstIP, icmp_message, ICMP_PROTO)

   
def initICMP():
    '''
        Nombre: initICMP
        Descripción: Esta función inicializa el nivel ICMP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_ICMP_message con el valor de protocolo 1

        Argumentos:
            -Ninguno
        Retorno: Ninguno
          
    '''
    registerIPProtocol(process_ICMP_message, ICMP_PROTO)
    
    return