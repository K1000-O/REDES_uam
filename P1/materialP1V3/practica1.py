'''
    practica1.py
    Muestra el tiempo de llegada de los primeros 50 paquetes a la interfaz especificada
    como argumento y los vuelca a traza nueva con tiempo actual.

    Autores:	Alejandro Raúl Hurtado <alejandror.hurtado@estudiante.uam.es>
				Camilo Jené <camilo.jenec@estudiante.uam.es>
    2022 EPS-UAM
'''

from rc1_pcap import *
import sys
import binascii
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import logging

ETH_FRAME_MAX = 1514
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
num_paquete = 0
TIME_OFFSET = 30*60

def signal_handler(nsignal,frame):
	logging.info('Control C pulsado')
	if handle:
		pcap_breakloop(handle)
		

def procesa_paquete(us,header,data):
	global num_paquete, pdumper

	# Fingimos que el paquete lo recibimos en el futuro. Cogemos el tiempo UNIX y le aumentamos 30 minutos.
	header.ts.tv_sec = int(time.time()) + (TIME_OFFSET) 

	logging.info('Nuevo paquete de {} bytes capturado en el timestamp UNIX {}.{}'.format(header.len,header.ts.tv_sec,header.ts.tv_sec))
	num_paquete += 1
	#TODO imprimir los N primeros bytes
	"""
	Guardamos los bytes de los paquetes de datos. Para ello creamos un
	array llamado lista en el que añadimos los datos en formato byte.
	"""
	lista = []
	for byte in data:
		lista.append('{:02x}'.format(byte))

	#Imprimimos cada byte, que ocupa 2 carácteres + el espacio.
	print(' '.join(lista)[:args.nbytes*3])

	#Escribir el tráfico al fichero de captura con el offset temporal
	if args.interface:
		pcap_dump(pdumper,header,data) # Introducimos los datos en el archivo específicado.

		ret = pcap_inject(handle, data, len(data)) # Envíamos el tráfico. Para comprobarlo el ret debe ser igual al size.
		if ret == len(data):
			print('Tráfico enviado de forma correcta.')
		else:
			print('Error al enviar el tráfico.')	
	
if __name__ == "__main__":
	global pdumper,args,handle
	parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz ( o lee de fichero) y muestra la longitud y timestamp de los 50 primeros paquetes',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile', default=False,help='Fichero pcap a abrir')
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--nbytes', dest='nbytes', type=int, default=14,help='Número de bytes a mostrar por paquete')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	if args.tracefile is False and args.interface is False:
		logging.error('No se ha especificado interfaz ni fichero')
		parser.print_help()
		sys.exit(-1)

	signal.signal(signal.SIGINT, signal_handler)

	errbuf = bytearray()
	handle = None
	pdumper = None
	
	#TODO abrir la interfaz especificada para captura o la traza
	if args.tracefile:	# Apertura de la traza anteriormente capturada.
		handle = pcap_open_offline(args.tracefile,errbuf)

	if args.interface:	# Apertura de la interfaz de captura.
		handle = pcap_open_live(args.interface,ETH_FRAME_MAX,NO_PROMISC,TO_MS, errbuf)
		
		#TODO abrir un dumper para volcar el tráfico (si se ha especificado interfaz) 
		dumper = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX)
		nombre = 'captura.'+args.interface+'.'+str(time.time())+'.pcap'
		pdumper = pcap_dump_open(dumper, nombre)
	
	ret = pcap_loop(handle,50,procesa_paquete,None)
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')
	logging.info('{} paquetes procesados'.format(num_paquete))
	
	#TODO si se ha creado un dumper cerra