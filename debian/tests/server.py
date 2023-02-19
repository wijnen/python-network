#!/usr/bin/python3

import fhs
import network

fhs.option('port', 'port to listen on', default = '8888')
config = fhs.init(help = 'testing program for network module', version = '0.1', contact = 'Bas Wijnen <wijnen@debian.org>')

class Connection:
	def __init__(self, remote):
		self.remote = remote
		self.remote.disconnect_cb(self.disconnected)
		self.remote.readlines(self.readline)
		self.remote.send(b"here's some data\n")
	def readline(self, line):
		print('Server received line:', line)
		if line == 'quit':
			self.remote.close()
	def disconnected(self, remote, data):
		print('Client disconnected from server')
		network.endloop()

server = network.Server(config['port'], Connection)
network.fgloop()
