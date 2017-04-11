#from OpenSSL import SSL
import socket
from user_agents import parse
import multiprocessing
import ssl
import sys
from datetime import *

class HTTP_Server(object):
	"""This is the http page spoofing Server"""
	def __init__(self, bind_address, bind_port, html_file):
		global http_responce, s, html
		super(HTTP_Server, self).__init__()
		with open('server.log', 'w') as f:
			f.write('')
			f.close()
		#TODO: Change responce content-type to relevant type
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		try:
			s.bind((bind_address, bind_port))
		except socket.error:
			sys.stdout.write("[\033[1;31m+\033[00m] Port {} already open... can\'t bind\n".format(bind_port))
			sys.exit(-1)
		s.listen(5)
		with open(html_file, 'r') as file:
			html = file.read()
			file.close()

	def _http_client_handler(self, *args):
		payloads_folder = ''.join(list(args))
		while True:
			try:
				sock, addr = s.accept()
			except KeyboardInterrupt: 
				exit(1)

			req = sock.recv(1024)
			data = req.decode('utf-8')
			with open('Server.log', 'a') as file:
				file.write(data)
				file.close()

			#Correctly parse the request line header
			try:
				request = data.split('\n', 1)[0]
				request_line = request.rstrip('\r\n')
				request_method, path, request_version = request_line.split()
			except ValueError:
				pass

			#Parse all the other main headers
			try:
				user_agent = data.splitlines()[2]
				Accept = data.splitlines()[3]
				Accept_Language = data.splitlines()[4]
				Accept_Encoding = data.splitlines()[5]
				Referer = data.splitlines()[6]
				Connection = data.splitlines()[7]
				Cache_Control = data.splitlines()[8]
			except IndexError:
				pass


			#Print Status Message
			ua = parse(user_agent)
			print("[ HTTP ]", "[" ,datetime.now(), "]", "[" ,addr[0], "]", "[", str(ua).replace(" / ", '-') ,"]", request)

			#Send File
			if path == '/':
				er_resp = """
HTTP/1.1 200 OK
Content-Type: text/html

{}
"""
				sock.sendall(er_resp.format(html).encode('utf-8'))
				sock.close()
			elif path == '/lock.png':
				err_resp = """
HTTP/1.1 200 OK
Content-Type: image/png

""".encode('utf-8')
				img_png = open(payloads_folder+path, 'rb')
				img = img_png.read()
				sock.send(err_resp+img)
				sock.close()
			
			else:
				try:
					e_resp = """
HTTP/1.1 200 OK
Content-Type: text/html

<link rel="icon" 
      type="image/png" 
      href="lock.png">

""".encode('utf-8')
					with open(payloads_folder+path, 'rb') as file:
						rfile = file.read()
						file.close()
						sock.send(e_resp+rfile)
						sock.close()
				except:
					pass


class SSL_Server(object):
	"""This is the https page spoofing Server"""
	def __init__(self, bind_address, bind_port, html_file, cert_file, key_file):
		global ssl_socket, bs
		super(SSL_Server, self).__init__()
		context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
		context.load_cert_chain(certfile=cert_file, keyfile=key_file)
		bs = socket.socket()
		bs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		#print("SSL -->", bind_address, bind_port)
		bs.bind((bind_address, bind_port))
		bs.listen(5)
		with open(html_file, 'r') as file:
			html = file.read()
			file.close()

	def _ssl_client_handler(self):
		while True:
			try:
				sock, addr = bs.accept()
			except KeyboardInterrupt: exit()
			rec = sock.recv(1024)
			#Drop SSL Connection Without error
			sock.send(bytes("200 OK\r\n".encode('utf-8')))


if __name__ == '__main__':
	http_Server = HTTP_Server('192.168.1.115', 9000, 'Payloads/payload.html')
	ssl_Server = SSL_Server('192.168.1.115', 4444, 'Payloads/payload.html')
	jobs = []
	for i in range (4):
		p = multiprocessing.Process(target=http_Server._http_client_handler)
		jobs.append(p)
		p.start()
		p2 = multiprocessing.Process(target=ssl_Server._ssl_client_handler())
		jobs.append(p2)
		p2.start()