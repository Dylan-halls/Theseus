from __future__ import print_function
from __future__ import division
import datetime
import socket
import time
import struct
import binascii
import argparse

class Arp_Ping(object):
	"""Run a Arp ping against the target to get there mac the give it to the arp cache poison"""
	def __init__(self, interface):
		global s, sent, rev
		sent = 0
		rev = 0
		super(Arp_Ping, self).__init__()
		s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
		try:
			s.bind((interface, socket.htons(0x0800)))
		except socket.error:
			print("\033[1;31mUnable to bind to interface... unknown type\033[00m")
			exit()

	def craft_packet(self, requested_ip=None, responce_to_ip=None, responce_to_mac=None, send_to_mac=None):
		#thanks to techb for help
		if requested_ip and responce_to_ip and responce_to_mac and send_to_mac != None:
			arp_header_code = '\x08\x06'
			target_ip = socket.inet_aton(requested_ip)
			target_mac = binascii.unhexlify(''.join(send_to_mac.split(':')))
			redirect_to_ip = socket.inet_aton(responce_to_ip)
			redirect_to_mac = binascii.unhexlify(''.join(responce_to_mac.split(':')))

			#Ethernet headers
			eth_head =  bytes(target_mac)+bytes(redirect_to_mac)+bytes(arp_header_code.encode('utf-8'))

			#Arp headers
			header_type = '\x00\x01'
			protocol = '\x08\x00'
			mac_size = '\x06'
			ip_size = '\x04'
			option_code = '\x00\x01'

			arp_head = header_type + protocol + mac_size + ip_size + option_code

			#Spoofed Bit
			spoofed_part = redirect_to_mac + redirect_to_ip + target_mac + target_ip
			#Final Packet
			arp_packet = bytes(eth_head) + bytes(arp_head.encode('utf-8')) + bytes(spoofed_part)
			return arp_packet

	def format_mac(self, bin_mac):
		temp = bin_mac.replace(":", "").replace("-", "").replace(".", "")
		return temp[:2] + ":" + ":".join([temp[i] + temp[i+1] for i in range(2,12,2)])

	def await_responce(self, iface):
		global rev
		r = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
		pkt = r.recvfrom(2048)
		
		eth = pkt[0][0:14]
		eth_d = struct.unpack("!6s6s2s", eth)
		res = binascii.hexlify(eth_d[0])

		dst_mac = self.format_mac(res.decode('utf-8'))

		local_mac = open('/sys/class/net/{}/address'.format(iface)).read().strip('\n')
 		
		if dst_mac == local_mac:
			stop_time = datetime.datetime.now()
			arp_h = pkt[0][14:42]
			arp_d = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_h)
			timee = stop_time - start_time
			rev += 1
			return self.format_mac(binascii.hexlify(arp_d[5]).decode('utf-8')), arp_d[6], timee.total_seconds() * 1000

	def ping(self, addr, local, iface):
		global start_time, sent
		local_mac = open('/sys/class/net/{}/address'.format(iface)).read().strip('\n')
		request_packet = self.craft_packet(requested_ip=addr, responce_to_ip=local, responce_to_mac=local_mac, send_to_mac='FF:FF:FF:FF:FF:FF')
		s.send(request_packet)
		start_time = datetime.datetime.now()
		sent += 1

if __name__ == '__main__':
	programme_start = datetime.datetime.now()
	print("\033[1;3mArping v1\033[00m")

	ap = argparse.ArgumentParser(description="Theseus")
	ap.add_argument("-t", help="This is the targets ip address", required=True)
	ap.add_argument("-i", help="This is the network cards current interface", required=True)
	args = ap.parse_args()

	p = Arp_Ping(args.i)

	times = []

	o = -1
	while True:
		try:
			o += 1
			p.ping(args.t)
			mac, ip, timee = p.await_responce(args.i)
			try:
				ip = socket.inet_ntop(socket.AF_INET, ip)
				pkt_from = socket.gethostbyaddr(ip)[0]
			except socket.error as e:
				print(type(e))

			print(pkt_from+': ('+ip, 'is at', mac+')', 'index='+str(o),'time='+str(timee)+'ms')
			times.append(timee)
			time.sleep(1)
		except KeyboardInterrupt:
			programme_stop = datetime.datetime.now()
			overall_time = programme_stop - programme_start
			avg = sum(times) / float(len(times))
			print("\n--- {} arping statistics ---".format(args.t))
			print("{} packets transmitted, {} packets received, time {}ms".format(sent, rev, overall_time.total_seconds() * 1000))
			print("min/avg/max = {}/{}/{}".format(min(times), avg, max(times)))
			exit()