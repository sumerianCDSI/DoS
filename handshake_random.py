#!/usr/bin/python3.5
# -*- coding=utf-8 -*-

#Ce script permet de simuler un établissement d'une connextion TCP avec une IP source aléatoire
#Voir handshank.py pour savoir plus

import sys
import logging
import re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def handshake_random(ip, port):
	source_port = random.randint(1024, 65535)
	init_sn = random.randint(1, 65535*63335)
    #Générer une adresse IP aléatoire
	ip1_section = random.randint(1, 254)
	ip2_section = random.randint(1, 254)
	ip3_section = random.randint(1, 254)
	ip4_section = random.randint(1, 254)
	source_ip = str(ip1_section)+'.'+str(ip2_section)+'.'+str(ip3_section)+'.'+str(ip4_section)
	try:
		result_raw_synack = sr(IP(src=source_ip,dst=ip)/TCP(dport=port,sport=source_port,flags=2,seq=init_sn), verbose = False)
		result_synack_list = result_raw_synack[0].res
		tcpfields_synack = result_synack_list[0][1][1].fields
		sc_sn = tcpfields_synack['seq'] + 1
		cs_sn = tcpfields_synack['ack']
		send(IP(src=source_ip,dst=ip)/TCP(dport=port,sport=source_port,flags=16,seq=cs_sn,ack=sc_sn), verbose = False)
	except:
		pass
		
if __name__ == '__main__':
	handshake_random('192.168.1.1', 80)
