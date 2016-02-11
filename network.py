# vim: set fileencoding=utf-8 foldmethod=marker :

'''Python module for easy networking.
This module intends to make networking easy.  It supports unix domain sockets
and TLS encryption.  Connection targets can be specified in several ways.  GLib
is used for all callbacks, so it must be installed for them to work.  Avahi is
supported if it is detected.
'''

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
fhs.module_init('network', {'tls': ''})

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
	'''Change target for log().
	By default, log() sends its output to standard error.  This function is
	used to change the target.
	@param file: The new file to write log output to.
	'''
	global log_output
	log_output = file
# }}}

def log(message): # {{{
	'''Log a message.
	Write a message to log (default standard error, can be changed with
	set_log_output()).  A timestamp is added before the message and a
	newline is added to it.
	@param message: The message to log.  This must be a str.  It should not contain a newline.
	'''
	t = time.strftime('%c %Z %z')
	log_output.write(''.join(['%s: %s\n' % (t, m) for m in message.split('\n')]))
	log_output.flush()
# }}}

def lookup(service): # {{{
	'''Convert int or str with int or service to int port.
	@service: int or numerical str or network service name.
	'''
	if isinstance(service, int):
		return service
	try:
		return socket.getservbyname(service)
	except socket.error:
		pass
	return int(service)
# }}}

class _Fake: # {{{
	'''File wrapper which can be used in place of a network.Socket.
	This class allows files (specifically sys.stdin and sys.stdout) to be
	used as a base for Socket.  Don't call this class directly, use
	wrap() instead.
	'''
	def __init__(self, i, o):
		'''Create a fake socket object.
		@param i: input file.
		@param o: output file.
		'''
		self._i = i
		self._o = o
	def close(self):
		'''Close the fake socket object.
		@return None.'''
		pass
	def sendall(self, data):
		'''Send data to fake socket object.
		@return None.'''
		while len(data) > 0:
			ret = os.write(self._o, data)
			if ret >= 0:
				data = data[ret:]
				continue
			log('network.py: Failed to write data')
			traceback.print_exc()
	def recv(self, maxsize):
		'''Receive data from fake socket object.
		@return Received data.'''
		#log('recv fake')
		return os.read(self._i.fileno(), maxsize)
	def fileno(self):
		'''Return file descriptor for select (only for reading).
		@return The file descriptor.'''
		# For reading.
		return self._i.fileno()
# }}}

def wrap(i, o): # {{{
	'''Wrap two files into a fake socket.
	This function wraps an input and an output file (which may be the same)
	into a Socket object.
	@param i: input file.
	@param o: output file.
	'''
	return Socket(_Fake(i, o))
# }}}

class Socket: # {{{
	'''Connection object.
	'''
	def __init__(self, address, tls = None, disconnect_cb = None, remote = None): # {{{
		'''Create a connection.
		@param address: connection target.  This is a unix domain
		socket if there is a / in it.  It is an avahi service if there
		is a | in it.  This is written as service|regexp, where regexp
		must match the long service name and can be empty to match all.
		If it is not a unix domain socket or an avahi service, it is
		port number or service name, optionally prefixed with a
		hostname and a :.  If no hostname is present, localhost is
		used.
		@param tls: whether TLS encryption should be used.  Can be True
		or False, or None to try encryption first and fall back to
		unencrypted.  Setting this to None may trigger an error message
		and may fail to connect to unencrypted sockets due to the
		encryption handshake not returning.
		@param disconnect_cb: callback function for when the connection
		is lost.
		@param remote: For internal use only.
		'''
		## read only variable which indicates whether TLS encryption is used on this socket.
		self.tls = tls
		## remote end of the network connection.
		self.remote = remote
		## underlying socket object.
		self.socket = None
		self._disconnect_cb = disconnect_cb
		self._event = None
		self._linebuffer = b''
		if isinstance(address, (_Fake, socket.socket)):
			#log('new %d' % id(address))
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
				self._setup_connection()
			else:
				raise EOFError('Avahi service not found')
		else:
			if isinstance(address, str) and ':' in address:
				host, port = address.rsplit(':', 1)
			else:
				host, port = 'localhost', address
			self.remote = (host, lookup(port))
			#log('remote %s' % str(self.remote))
			self._setup_connection()
	# }}}
	def _setup_connection(self): # {{{
		'''Internal function to set up a connection.'''
		self.socket = socket.create_connection(self.remote)
		if self.tls is None:
			try:
				assert have_ssl
				self.socket = ssl.wrap_socket(self.socket, ssl_version = ssl.PROTOCOL_TLSv1)
				self.tls = True
			except:
				self.tls = False
				self.socket = socket.create_connection(self.remote)
		elif self.tls is True:
			try:
				assert have_ssl
				self.socket = ssl.wrap_socket(self.socket, ssl_version = ssl.PROTOCOL_TLSv1)
			except ssl.SSLError as e:
				raise TypeError('Socket does not seem to support TLS: ' + str(e))
		else:
			self.tls = False
	# }}}
	def disconnect_cb(self, disconnect_cb): # {{{
		'''Change the callback for disconnect notification.
		@param disconnect_cb: the new callback.
		@return None.'''
		self._disconnect_cb = disconnect_cb
	# }}}
	def close(self): # {{{
		'''Close the network connection.
		@return The data that was remaining in the line buffer, if any.'''
		if not self.socket:
			return b''
		data = self.unread()
		self.socket.close()
		self.socket = None
		if self._disconnect_cb:
			return self._disconnect_cb(self, data) or b''
		return data
	# }}}
	def send(self, data): # {{{
		'''Send data over the network.
		Send data over the network.  Block until all data is in the buffer.
		@param data: data to write.  This should be of type bytes.
		@return None.
		'''
		if self.socket is None:
			return
		#print 'sending %s' % repr(data)
		self.socket.sendall(data)
	# }}}
	def sendline(self, data): # {{{
		'''Send a line of text.
		Identical to send(), but data is a str and a newline is added.
		@param data: line to send.  A newline is added.  This should be
			of type str.  The data is sent as utf-8.
		@return None.
		'''
		if self.socket is None:
			return
		#print 'sending %s' % repr(data)
		self.socket.sendall((data + '\n').encode('utf-8'))
	# }}}
	def recv(self, maxsize = 4096): # {{{
		'''Read data from the network.
		Data is read from the network.  If the socket is not set to
		non-blocking, this call will block if there is no data.  It
		will return a short read if limited data is available.  The
		read data is returned as a bytes object.  If TLS is enabled,
		more than maxsize bytes may be returned.  On EOF, the socket is
		closed and if disconnect_cb is not set, an EOFError is raised.
		@param maxsize: passed to the underlaying recv call.  If TLS is
			enabled, no data is left pending, which means that more
			than maxsize bytes can be returned.
		@return The received data as a bytes object.
		'''
		if self.socket is None:
			log('recv on closed socket')
			raise EOFError('recv on closed socket')
		ret = b''
		try:
			ret = self.socket.recv(maxsize)
			if hasattr(self.socket, 'pending'):
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
		'''Register function to be called when data is ready for reading.
		The function will be called when data is ready.  The callback
		must read the function or call unread(), or it will be called
		again after returning.
		@param callback: function to be called when data can be read.
		@return The data that was remaining in the line buffer, if any.
		'''
		assert have_glib
		if self.socket is None:
			return b''
		ret = self.unread()
		self._callback = (callback, None)
		self._event = GLib.io_add_watch(self.socket.fileno(), GLib.IO_IN | GLib.IO_PRI | GLib.IO_HUP | GLib.IO_ERR, lambda fd, cond: (callback() or True))
		return ret
	# }}}
	def read(self, callback, maxsize = 4096): # {{{
		'''Register function to be called when data is received.
		When data is available, read it and call this function.  The
		data that was remaining in the line buffer, if any, is sent to
		the callback immediately.
		@param callback: function to call when data is available.  The
		data is passed as a parameter.
		@param maxsize: buffer size that is used for the recv call.
		@return None.
		'''
		assert have_glib
		if self.socket is None:
			return b''
		first = self.unread()
		self._maxsize = maxsize
		self._callback = (callback, False)
		def cb(fd, cond):
			data = self.recv(self._maxsize)
			#log('network read %d bytes' % len(data))
			if not self._event:
				return False
			callback(data)
			return True
		self._event = GLib.io_add_watch(self.socket.fileno(), GLib.IO_IN | GLib.IO_PRI | GLib.IO_HUP | GLib.IO_ERR, cb)
		if first:
			callback(first)
	# }}}
	def readlines(self, callback, maxsize = 4096): # {{{
		'''Buffer incoming data until a line is received, then call a function.
		When a newline is received, all data up to that point is
		decoded as an utf-8 string and passed to the callback.
		@param callback: function that is called when a line is
		received.  The line is passed as a str parameter.
		@param maxsize: used for the recv calls that are made.  The
		returned data accumulates until a newline is received; this is
		not a limit on the line length.
		@return None.
		'''
		assert have_glib
		if self.socket is None:
			return
		self._linebuffer = self.unread()
		self._maxsize = maxsize
		self._callback = (callback, True)
		self._event = GLib.io_add_watch(self.socket.fileno(), GLib.IO_IN | GLib.IO_PRI | GLib.IO_HUP | GLib.IO_ERR, lambda fd, cond: (self._line_cb() or True))
	# }}}
	def _line_cb(self): # {{{
		self._linebuffer += self.recv(self.maxsize)
		while b'\n' in self._linebuffer and self._event:
			assert self._callback[1] is not None	# Going directly from readlines() to rawread() is not allowed.
			if self._callback[1]:
				line, self._linebuffer = self._linebuffer.split(b'\n', 1)
				line = makestr(line)
				self._callback[0] (line)
			else:
				data = makestr(self._linebuffer)
				self._linebuffer = b''
				self._callback[0](data)
	# }}}
	def unread(self): # {{{
		'''Cancel a read() or rawread() callback.
		Cancel any read callback.
		@return Bytes left in the line buffer, if any.  The line buffer
			is cleared.
		'''
		if self._event:
			GLib.source_remove(self._event)
			self._event = None
		ret = self._linebuffer
		self._linebuffer = b''
		return ret
	# }}}
# }}}

if have_glib:	# {{{
	class Server: # {{{
		'''Listen on a network port and accept connections.  Optionally register an avahi service.'''
		def __init__(self, port, obj, address = '', backlog = 5, tls = None, disconnect_cb = None):
			'''Start a server.
			@param port: Port to listen on.  Can be an avahi
				service as "name|description" or a unix domain socket,
				or a numerical port or service name.
			@param obj: Object to create when a new connection is
				accepted.  The new object gets the nex Socket
				as parameter.  This can be a function instead
				of an object.
			@param address: Address to listen on.  If empty, listen
				on all IPv4 and IPv6 addresses.  If IPv6 is not
				supported, set this to "0.0.0.0" to listen only
				on IPv4.
			@param backlog: Number of connections that are accepted
				by the kernel while waiting for the program to
				handle them.
			@param tls: Whether TLS encryption should be enabled.
				If False or "-", it is disabled.  If True, it
				is enabled with the default hostname.  If None
				or "", it is enabled if possible.  If a str, it
				is enabled with that string used as hostname.
				New keys are generated if they are not
				available.  If you are serving to the internet,
				it is a good idea to get them signed by a
				certificate authority.  They are in
				~/.local/share/network/.
			@param disconnect_cb: Function which is called when a
				socket loses its connection.  It receives the
				socket and any data that was remaining in the
				buffer as an argument.
			'''
			self._disconnect_cb = disconnect_cb
			self._group = None
			self._obj = obj
			## Port that is listened on. (read only)
			self.port = ''
			## Whether the server listens for IPv6. (read only)
			self.ipv6 = False
			self._socket = None
			## False or the hostname for which the TLS keys are used. (read only)
			self.tls = tls
			## Currently active connections for this server. (read only set, but elements may be changed)
			self.connections = set()
			if isinstance(port, str) and '/' in port:
				# Unix socket.
				# TLS is ignored for these sockets.
				self.tls = False
				self._socket = socket.socket(socket.AF_UNIX)
				self._socket.bind(port)
				self.port = port
				self._socket.listen(backlog)
			elif have_avahi and isinstance(port, str) and '|' in port:
				self._tls_init()
				self._socket = socket.socket()
				self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				if address == '':
					self._socket6 = socket.socket(socket.AF_INET6)
					self._socket6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				info = port.split('|')
				self.port = port
				if len(info) > 2:
					self._socket.bind((address, lookup(info[2])))
				self._socket.listen(backlog)
				if address == '':
					p = self._socket.getsockname()[1]
					self._socket6.bind(('::1', p))
					self._socket6.listen(backlog)
					self.ipv6 = True
				bus = dbus.SystemBus()
				server = dbus.Interface(bus.get_object(avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER), avahi.DBUS_INTERFACE_SERVER)
				self._group = dbus.Interface(bus.get_object(avahi.DBUS_NAME, server.EntryGroupNew()), avahi.DBUS_INTERFACE_ENTRY_GROUP)
				self._group.AddService(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, dbus.UInt32(0), info[1], '_%s._tcp' % info[0], '', '', dbus.UInt16(self._socket.getsockname()[1]), '')
				self._group.Commit()
			else:
				self._tls_init()
				port = lookup(port)
				self._socket = socket.socket()
				self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				self._socket.bind((address, port))
				self._socket.listen(backlog)
				if address == '':
					self._socket6 = socket.socket(socket.AF_INET6)
					self._socket6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
					self._socket6.bind(('::1', port))
					self._socket6.listen(backlog)
					self.ipv6 = True
				self.port = port
			fd = self._socket.fileno()
			GLib.io_add_watch(fd, GLib.IO_IN | GLib.IO_PRI | GLib.IO_HUP | GLib.IO_ERR, self._cb)
			if self.ipv6:
				fd = self._socket6.fileno()
				GLib.io_add_watch(fd, GLib.IO_IN | GLib.IO_PRI | GLib.IO_HUP | GLib.IO_ERR, self._cb)
		def set_disconnect_cb(self, disconnect_cb):
			'''Change the function that is called when a socket disconnects.
			@param disconnect_cb: the new callback function.
			@return None.
			'''
			self._disconnect_cb = disconnect_cb
		def _cb(self, fd, cond):
			if fd == self._socket.fileno():
				new_socket = self._socket.accept()
			else:
				new_socket = self._socket6.accept()
			#log('Accepted connection from %s; possibly attempting to set up encryption' % repr(new_socket))
			if self.tls:
				assert have_ssl
				try:
					new_socket = (ssl.wrap_socket(new_socket[0], ssl_version = ssl.PROTOCOL_TLSv1, server_side = True, certfile = self._tls_cert, keyfile = self._tls_key), new_socket[1])
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
			s = Socket(new_socket[0], remote = new_socket[1], disconnect_cb = self._handle_disconnect)
			self.connections.add(s)
			self._obj(s)
			return True
		def _handle_disconnect(self, socket, data):
			#log('Closed connection to %s' % repr(socket.remote))
			self.connections.remove(socket)
			if self._disconnect_cb:
				return self._disconnect_cb(socket, data)
			return data
		def close(self):
			'''Stop the server.
			@return None.
			'''
			if self._group:
				self._group.Reset()
				self._group = None
			self._socket.close()
			self._socket = None
			if self.ipv6:
				self._socket6.close()
				self._socket6 = None
			if '/' in self.port:
				os.remove(self.port)
			self.port = ''
		def __del__(self):
			'''Stop the server.
			@return None.
			'''
			if self._socket is not None:
				self.close()
		def _tls_init(self):
			# Set up members for using tls, if requested.
			if self.tls in (False, '-'):
				self.tls = False
				return
			if self.tls in (None, True, ''):
				self.tls = fhs.module_get_config('network')['tls']
			if self.tls == '':
				self.tls = socket.getfqdn()
			elif self.tls == '-':
				self.tls = False
				return
			# Use tls.
			fc = fhs.read_data(os.path.join('certs', self.tls + os.extsep + 'pem'), opened = False, packagename = 'network')
			fk = fhs.read_data(os.path.join('private', self.tls + os.extsep + 'key'), opened = False, packagename = 'network')
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
			self._tls_cert = fc
			self._tls_key = fk
			#print(fc, fk)
	# }}}

	_loop = None
	def fgloop(timeout = None): # {{{
		'''Wait for events and handle them.
		This function does not fork into the background like bgloop().
		@param timeout: if not None, the function returns when the
			timeout (in seconds) expires.
		@return True if the timeout was reached, False if the loop was
			stopped for a different reason.
		'''
		global _loop
		assert _loop is None
		_loop = GLib.MainLoop()
		notify = []
		if timeout is not None:
			_timeout = GLib.timeout_add(timeout * 1000, lambda: notify.append(True) or (endloop() and False))
		_loop.run()
		if len(notify) > 0:
			return True
		if timeout is not None:
			GLib.source_remove(_timeout)
		return False
	# }}}

	def bgloop(): # {{{
		'''Like fgloop, but forks to the background.
		Unlike fgloop(), this function does not support a timeout.
		If the environment variable NETWORK_NO_FORK is set, it will
		remain in the foreground.
		@return None.'''
		if os.getenv('NETWORK_NO_FORK') is None:
			if os.fork() != 0:
				sys.exit(0)
		else:
			log('Not backgrounding because NETWORK_NO_FORK is set\n')
		fgloop()
	# }}}

	def endloop(): # {{{
		'''Stop a loop that was started with fgloop() or bgloop().
		@return None.
		'''
		global _loop
		assert _loop is not None
		_loop.quit()
		_loop = None
	# }}}

	def iteration(): # {{{
		'''Do a single iteration of the GLib main loop.  Do not block.
		@return None.'''
		GLib.MainContext().iteration(False)
	# }}}
# }}}
