# Python module for easy networking.
# vim: set fileencoding=utf-8 foldmethod=marker :

# {{{ Copyright 2012 Bas Wijnen <wijnen@debian.org>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or(at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# }}}

# {{{ Imports.
import sys
import os
import socket
import select
import re
import time
import fhs
try:
	import ssl
	have_ssl = True
except:
	have_ssl = False
try:
	try:
		from gi.repository import GLib
	except ImportError:
		import glib as GLib
	have_glib = True
	try:
		import avahi
		import dbus
		from dbus.mainloop.glib import DBusGMainLoop
		have_avahi = True
	except:
		have_avahi = False
except:
	have_avahi = False
	have_glib = False
# }}}

# {{{ Interface description
# - connection setup
#   - connect to server
#   - listen on port
# - when connected
#   - send data
#   - asynchronous read
#   - blocking read for data

# implementation:
# - Server: listener, creating Sockets on accept
# - Socket: used for connection; symmetric
# }}}

if sys.version >= '3':
	makestr = lambda x: str(x, 'utf8', 'replace') if isinstance(x, bytes) else x
else:
	makestr = lambda x: x

log_output = sys.stderr

def set_log_output(file): # {{{
	global log_output
	log_output = file
# }}}

def log(message): # {{{
	t = time.strftime('%c %Z %z')
	log_output.write(''.join(['%s: %s\n' % (t, m) for m in message.split('\n')]))
	log_output.flush()
# }}}

def lookup(service): # {{{
	if isinstance(service, int):
		return service
	try:
		return socket.getservbyname(service)
	except socket.error:
		pass
	return int(service)
# }}}

class Socket: # {{{
	def __init__(self, address, tls = None, disconnect_cb = None, remote = None): # {{{
		self.tls = tls
		self.remote = remote
		self._disconnect_cb = disconnect_cb
		self.event = None
		self._linebuffer = b''
		if isinstance(address, socket.socket):
			self.socket = address
			return
		if isinstance(address, str) and '/' in address:
			# Unix socket.
			# TLS is ignored for those.
			self.remote = address
			self.socket = socket.socket(socket.AF_UNIX)
			self.socket.connect(self.remote)
		elif have_avahi and isinstance(address, str) and '|' in address:
			# Avahi.
			ret = []
			found = [False]
			info = address.split('|')
			assert len(info) == 2
			regexp = re.compile(info[1])
			type = '_%s._tcp' % info[0]
			bus = dbus.SystemBus(mainloop = DBusGMainLoop())
			server = dbus.Interface(bus.get_object(avahi.DBUS_NAME, '/'), 'org.freedesktop.Avahi.Server')
			browser = dbus.Interface(bus.get_object(avahi.DBUS_NAME, server.ServiceBrowserNew(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, type, 'local', dbus.UInt32(0))), avahi.DBUS_INTERFACE_SERVICE_BROWSER)
			def handle2(*args):
				self.remote = (str(args[5]), int(args[8]))
				mainloop.quit()
			def handle_error(*args):
				log('avahi lookup error(ignored): %s' % args[0])
			def handle(interface, protocol, name, type, domain, flags):
				if found[0]:
					return
				if regexp.match(name):
					found[0] = True
					server.ResolveService(interface, protocol, name, type, domain, avahi.PROTO_UNSPEC, dbus.UInt32(0), reply_handler = handle2, error_handler = handle_error)
			def handle_eof():
				if found[0]:
					return
				self.remote = None
				mainloop.quit()
			browser.connect_to_signal('ItemNew', handle)
			browser.connect_to_signal('AllForNow', handle_eof)
			browser.connect_to_signal('Failure', handle_eof)
			mainloop = GLib.MainLoop()
			mainloop.run()
			if self.remote is not None:
				self.setup_connection()
			else:
				raise EOFError('Avahi service not found')
		else:
			if isinstance(address, str) and ':' in address:
				host, port = address.rsplit(':', 1)
			else:
				host, port = 'localhost', address
			self.remote = (host, lookup(port))
			#log('remote %s' % str(self.remote))
			self.setup_connection()
	# }}}
	def setup_connection(self): # {{{
		self.socket = socket.create_connection(self.remote)
		if self.tls is None:
			try:
				assert have_ssl
				self.socket = ssl.wrap_socket(self.socket, ssl_version = ssl.PROTOCOL_TLSv1)
			except:
				self.socket = socket.create_connection(self.remote)
		elif self.tls is True:
			try:
				assert have_ssl
				self.socket = ssl.wrap_socket(self.socket, ssl_version = ssl.PROTOCOL_TLSv1)
			except ssl.SSLError as e:
				raise TypeError('Socket does not seem to support TLS: ' + str(e))
	# }}}
	def disconnect_cb(self, disconnect_cb): # {{{
		self._disconnect_cb = disconnect_cb
	# }}}
	def close(self): # {{{
		if not self.socket:
			return
		data = self.unread()
		self.socket.close()
		self.socket = None
		if self._disconnect_cb:
			return self._disconnect_cb(self, data)
		return data
	# }}}
	def send(self, data): # {{{
		if self.socket is None:
			return
		#print 'sending %s' % repr(data)
		self.socket.sendall(data)
	# }}}
	def recv(self, maxsize = 4096): # {{{
		if self.socket is None:
			return b''
		ret = b''
		try:
			ret = self.socket.recv(maxsize)
			while self.socket.pending():
				ret += self.socket.recv(maxsize)
		except:
			log('Error reading from socket: %s' % sys.exc_info()[1])
			self.close()
			return ret
		if len(ret) == 0:
			ret = self.close()
			if not self._disconnect_cb:
				raise EOFError('network connection closed')
		return ret
	# }}}
	def rawread(self, callback): # {{{
		assert have_glib
		if self.socket is None:
			return b''
		ret = self.unread()
		self.callback = (callback, None)
		self.event = GLib.io_add_watch(self.socket.fileno(), GLib.IO_IN | GLib.IO_PRI, lambda fd, cond: (callback() or True))
		return ret
	# }}}
	def read(self, callback, maxsize = 4096): # {{{
		assert have_glib
		if self.socket is None:
			return b''
		first = self.unread()
		self.maxsize = maxsize
		self.callback = (callback, False)
		def cb(fd, cond):
			data = self.recv(self.maxsize)
			#print('network read %d bytes' % len(data))
			if not self.event:
				#print('stopping')
				return False
			callback(data)
			return True
		self.event = GLib.io_add_watch(self.socket.fileno(), GLib.IO_IN | GLib.IO_PRI, cb)
		if first:
			callback(first)
	# }}}
	def readlines(self, callback, maxsize = 4096): # {{{
		assert have_glib
		if self.socket is None:
			return
		self._linebuffer = self.unread()
		self.maxsize = maxsize
		self.callback = (callback, True)
		self.event = GLib.io_add_watch(self.socket.fileno(), GLib.IO_IN | GLib.IO_PRI, lambda fd, cond: (self._line_cb() or True))
	# }}}
	def _line_cb(self): # {{{
		self._linebuffer += self.recv(self.maxsize)
		while b'\n' in self._linebuffer and self.event:
			assert self.callback[1] is not None	# Going directly from readlines() to rawread() is not allowed.
			if self.callback[1]:
				line, self._linebuffer = self._linebuffer.split(b'\n', 1)
				line = makestr(line)
				self.callback[0] (line)
			else:
				data = makestr(self._linebuffer)
				self._linebuffer = b''
				self.callback[0](data)
	# }}}
	def unread(self): # {{{
		if self.event:
			GLib.source_remove(self.event)
			self.event = None
		ret = self._linebuffer
		self._linebuffer = b''
		return ret
	# }}}
# }}}

if have_glib:	# {{{
	class Server: # {{{
		def __init__(self, port, obj, address = '', backlog = 5, tls = None, disconnect_cb = None):
			'''Listen on a port and accept connections.  Set tls to a key+certificate file to use tls.'''
			self._disconnect_cb = disconnect_cb
			self.group = None
			self.obj = obj
			self.port = ''
			self.ipv6 = False
			self.socket = None
			self.tls = tls
			self.connections = set()
			if isinstance(port, str) and '/' in port:
				# Unix socket.
				# TLS is ignored for these sockets.
				self.tls = False
				self.socket = socket.socket(socket.AF_UNIX)
				self.socket.bind(port)
				self.port = port
				self.socket.listen(backlog)
			elif have_avahi and isinstance(port, str) and '|' in port:
				self._tls_init()
				self.socket = socket.socket()
				self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				if address == '':
					self.socket6 = socket.socket(socket.AF_INET6)
					self.socket6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				info = port.split('|')
				self.port = port
				if len(info) > 2:
					self.socket.bind((address, lookup(info[2])))
				self.socket.listen(backlog)
				if address == '':
					p = self.socket.getsockname()[1]
					self.socket6.bind(('::1', p))
					self.socket6.listen(backlog)
					self.ipv6 = True
				bus = dbus.SystemBus()
				server = dbus.Interface(bus.get_object(avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER), avahi.DBUS_INTERFACE_SERVER)
				self.group = dbus.Interface(bus.get_object(avahi.DBUS_NAME, server.EntryGroupNew()), avahi.DBUS_INTERFACE_ENTRY_GROUP)
				self.group.AddService(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, dbus.UInt32(0), info[1], '_%s._tcp' % info[0], '', '', dbus.UInt16(self.socket.getsockname()[1]), '')
				self.group.Commit()
			else:
				self._tls_init()
				port = lookup(port)
				self.socket = socket.socket()
				self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				self.socket.bind((address, port))
				self.socket.listen(backlog)
				if address == '':
					self.socket6 = socket.socket(socket.AF_INET6)
					self.socket6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
					self.socket6.bind(('::1', port))
					self.socket6.listen(backlog)
					self.ipv6 = True
				self.port = port
			fd = self.socket.fileno()
			GLib.io_add_watch(fd, GLib.IO_IN | GLib.IO_PRI, self._cb)
			if self.ipv6:
				fd = self.socket6.fileno()
				GLib.io_add_watch(fd, GLib.IO_IN | GLib.IO_PRI, self._cb)
		def set_disconnect_cb(self, disconnect_cb):
			self._disconnect_cb = disconnect_cb
		def _cb(self, fd, cond):
			if fd == self.socket.fileno():
				new_socket = self.socket.accept()
			else:
				new_socket = self.socket6.accept()
			#log('Accepted connection from %s; possibly attempting to set up encryption' % repr(new_socket))
			if self.tls:
				assert have_ssl
				try:
					new_socket = (ssl.wrap_socket(new_socket[0], ssl_version = ssl.PROTOCOL_TLSv1, server_side = True, certfile = self.tls_cert, keyfile = self.tls_key), new_socket[1])
				except ssl.SSLError as e:
					log('Rejecting (non-TLS?) connection for %s: %s' % (repr(new_socket[1]), str(e)))
					try:
						new_socket[0].shutdown(socket.SHUT_RDWR)
					except:
						# Ignore errors here.
						pass
					return True
				except socket.error as e:
					log('Rejecting connection for %s: %s' % (repr(new_socket[1]), str(e)))
					try:
						new_socket[0].shutdown(socket.SHUT_RDWR)
					except:
						# Don't care about errors on shutdown.
						pass
					return True
				#log('Accepted TLS connection from %s' % repr(new_socket[1]))
			s = Socket(new_socket[0], remote = new_socket[1], disconnect_cb = lambda data: self._handle_disconnect(s, data))
			self.connections.add(s)
			self.obj(s)
			return True
		def _handle_disconnect(self, socket, data):
			#log('Closed connection to %s' % repr(socket.remote))
			self.connections.remove(socket)
			if self._disconnect_cb:
				return self._disconnect_cb(socket, data)
			return data
		def close(self):
			if self.group:
				self.group.Reset()
				self.group = None
			self.socket.close()
			self.socket = None
			if self.ipv6:
				self.socket6.close()
				self.socket6 = None
			if '/' in self.port:
				os.remove(self.port)
			self.port = ''
		def __del__(self):
			if self.socket is not None:
				self.close()
		def _tls_init(self):
			# Set up members for using tls, if requested.
			self.tls = fhs.init(packagename = 'network', config = {'tls': ''}, argv = os.getenv('NETWORK_OPTS', '').split())['tls']
			if self.tls == '':
				self.tls = socket.getfqdn()
			elif self.tls == '-':
				self.tls = False
				return
			# Use tls.
			fc = fhs.read_data(os.path.join('certs', self.tls + os.extsep + 'pem'), opened = False, packagename = 'network')
			fk = fhs.read_data(os.path.join('private', self.tls + os.extsep + 'key'), opened = False)
			if fc is None or fk is None:
				# Create new self-signed certificate.
				certfile = fhs.write_data(os.path.join('certs', self.tls + os.extsep + 'pem'), opened = False, packagename = 'network')
				csrfile = fhs.write_data(os.path.join('csr', self.tls + os.extsep + 'csr'), opened = False, packagename = 'network')
				for p in (certfile, csrfile):
					path = os.path.dirname(p)
					if not os.path.exists(path):
						os.makedirs(path)
				keyfile = fhs.write_data(os.path.join('private', self.tls + os.extsep + 'key'), opened = False, packagename = 'network')
				path = os.path.dirname(keyfile)
				if not os.path.exists(path):
					os.makedirs(path, 0o700)
				os.system('openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -subj "/CN=%s" -keyout "%s" -out "%s"' % (self.tls, keyfile, certfile))
				os.system('openssl req -subj "/CN=%s" -new -key "%s" -out "%s"' % (self.tls, keyfile, csrfile))
				fc = fhs.read_data(os.path.join('certs', self.tls + os.extsep + 'pem'), opened = False, packagename = 'network')
				fk = fhs.read_data(os.path.join('private', self.tls + os.extsep + 'key'), opened = False, packagename = 'network')
			self.tls_cert = fc
			self.tls_key = fk
			#print(fc, fk)
	# }}}

	_loop = None
	def fgloop(): # {{{
		global _loop
		assert _loop is None
		_loop = GLib.MainLoop()
		_loop.run()
	# }}}

	def bgloop(): # {{{
		if os.getenv('NETWORK_NO_FORK') is None:
			if os.fork() != 0:
				sys.exit(0)
		else:
			log('Not backgrounding because NETWORK_NO_FORK is set\n')
		fgloop()
	# }}}

	def endloop(): # {{{
		global _loop
		assert _loop is not None
		_loop.quit()
		_loop = None
	# }}}

	def iteration(): # {{{
		GLib.MainContext().iteration(False)
	# }}}
# }}}
