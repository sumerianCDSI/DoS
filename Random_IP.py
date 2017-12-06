#!/usr/bin/python3.5
# -*- coding=utf-8 -*-

#Ce script permet de générer une adresse IP aléatoire

import random

#Une adresse IP se compose de quatre octets (x.x.x.x)
#On définit une fonction qui choisit un nombre entre 1 et 254
def Random_Section():
	section = random.randint(1, 254)
	return section

#On regroupe les 4 octets
def Random_IP():
	IP = str(Random_Section())+'.'+str(Random_Section())+'.'+str(Random_Section())+'.'+str(Random_Section())
	return IP

if __name__ == '__main__':
	print(Random_IP())
