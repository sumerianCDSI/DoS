#!/usr/bin/python3.5
# -*- coding=utf-8 -*-

#Établissement d'une connexion TCP
#1. Le client envoie un segment SYN au serveur,
#2. Le serveur lui répond par un segment SYN/ACK
#3. Le client confirme par un segment ACK

#Ce script permet de simuler un établissment d'une connextion TCP


import sys
import logging
import re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#Ignorer l'erreur de IPv6 lors l'utilisation de Scapy
from scapy.all import *

def handshake(ip, port):#TCP 3 ways handshake
	source_port = random.randint(1024, 65535)#Source Port
	init_sn = random.randint(1, 65535*63335)#TCP Seq Number
	try:
		#Envoyer un paquet SYN (flag=2)
		result_raw_synack = sr(IP(dst=ip)/TCP(dport=port,sport=source_port,flags=2,seq=init_sn), verbose = False)
		#Mettre l'info réçue dans une liste ([0] répondu，[1] non répondu)
		result_synack_list = result_raw_synack[0].res
		#Filtrer l'info de TCP
		tcpfields_synack = result_synack_list[0][1][1].fields
        #Règle: Syn ou Fin compte 1 bit
		sc_sn = tcpfields_synack['seq'] + 1
		cs_sn = tcpfields_synack['ack']
		#Envoyer un paquet ACK (flag = 16)
		send(IP(dst=ip)/TCP(dport=port,sport=source_port,flags=16,seq=cs_sn,ack=sc_sn), verbose = False)
	except:
		pass

if __name__ == '__main__':
	handshake('192.168.1.1', 80)
