import socket
from user_agents import parse
import multiprocessing
import ssl
import sys
from datetime import *

class HTTP_Server(object):
	"""This is the http page spoofing Server"""
	def __init__(self, bind_address, payloads_folder):
		global http_responce, s, html
		super(HTTP_Server, self).__init__()
		bind_port = 9000
		with open('server.log', 'w') as f:
			f.write('')
			f.close()
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		try:
			s.bind((bind_address, bind_port))
		except socket.error:
			sys.stdout.write("[\033[1;31m+\033[00m] Port {} already open... can\'t bind\n".format(bind_port))
			sys.exit(-1)
		s.listen(5)
		with open(payloads_folder+'/payload.html', 'r') as file:
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
				path = ' '

			#Parse all the other main headers
			try:
				#user_agent = data.splitlines()[2]
				user_agent = ''.join([i[12:] for i in data.splitlines() if 'User-Agent:' in i])
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
				html_e_resp = """
HTTP/1.1 200 OK
Content-Type: text/html

""".encode('utf-8')

				e_resp = """
HTTP/1.1 200 OK

""".encode('utf-8')
				try:
					with open(payloads_folder+path, 'rb') as file:
						rfile = file.read()
						file.close()
						sock.send(e_resp+rfile)
						sock.close()
				except FileNotFoundError:
					sock.sendall(html_e_resp+html.encode('utf-8'))
					sock.close()