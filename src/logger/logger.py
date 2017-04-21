import sys

class Logger(object):
	"""docstring for Logger"""
	def __init__(self):
		super(Logger, self).__init__()
		pass

	def status(self, *args):
		print("\033[1;34m•\033[00m", ''.join([i for i in args]))

	def warn(self, *args):
		print("\033[1;33m•\033[00m", ''.join([i for i in args]))

	def critical(self, *args):
		print("\033[1;31m•\033[00m", ''.join([i for i in args]))
