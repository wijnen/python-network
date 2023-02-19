#!/usr/bin/python3

import fhs
import network

fhs.option('port', 'port to connect to', default = '8888')
config = fhs.init(help = 'testing program for network module', version = '0.1', contact = 'Bas Wijnen <wijnen@debian.org>')

def readline(line):
	print('Client received line:', line)
	client.send(b'quit\n')

def disconnected(remote, data):
	print('Server disconnected from client')
	network.endloop()

client = network.Socket(config['port'], tls = False)
client.disconnect_cb(disconnected)
client.readlines(readline)

network.fgloop()
