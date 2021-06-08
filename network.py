# vim: set fileencoding=utf-8 foldmethod=marker :

# {{{ Copyright 2013-2019 Bas Wijnen <wijnen@debian.org>
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

'''@mainpage
Python-network is a module which intends to make networking easy.  It supports
tcp and unix domain sockets.  Connection targets can be specified in several
ways.
'''

'''@file
Python module for easy networking.  This module intends to make networking
easy.  It supports tcp and unix domain sockets.  Connection targets can be
specified in several ways.
'''

'''@package network Python module for easy networking.
This module intends to make networking easy.  It supports tcp and unix domain
sockets.  Connection targets can be specified in several ways.
'''

# {{{ Imports.
import math
import sys
import os
import socket
import select
import re
import time
import inspect
import fhs
modulename = 'network'
fhs.module_info(modulename, 'Networking made easy', '0.2', 'Bas Wijnen <wijnen@debian.org>')
fhs.module_option(modulename, 'tls', 'tls hostname for server sockets or True/False for client sockets. Set to - to disable tls on server. If left empty, uses hostname for server, True for client sockets.', default = '')
import traceback

try:
	import ssl
	have_ssl = True
except:
	have_ssl = False
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
log_date = False

def set_log_output(file): # {{{
	'''Change target for log().
	By default, log() sends its output to standard error.  This function is
	used to change the target.
	@param file: The new file to write log output to.
	@return None.
	'''
	global log_output, log_date
	log_output = file
	log_date = True
# }}}

def log(*message, filename = None, line = None, funcname = None, depth = 0): # {{{
	'''Log a message.
	Write a message to log (default standard error, can be changed with
	set_log_output()).  A timestamp is added before the message and a
	newline is added to it.
	@param message: The message to log. Multiple arguments are logged on separate lines. Newlines in arguments cause the message to be split, so they should not contain a closing newline.
	@param filename: Override filename to report.
	@param line: Override line number to report.
	@param funcname: Override function name to report.
	@param depth: How deep to enter into the call stack for function info.
	@return None.
	'''
	t = time.strftime('%F %T' if log_date else '%T')
	source = inspect.currentframe().f_back
	for d in range(depth):
		source = source.f_back
	code = source.f_code
	if filename is None:
		filename = os.path.basename(code.co_filename)
	if funcname is None:
		funcname = code.co_name
	if line is None:
		line = source.f_lineno
	for msg in message:
		log_output.write(''.join(['%s %s:%s:%d:\t%s\n' % (t, filename, funcname, line, m) for m in str(msg).split('\n')]))
	log_output.flush()
# }}}

def lookup(service): # {{{
	'''Convert int or str with int or service to int port.
	@param service: int or numerical str or network service name.
	@return the port number for the service as an int.
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
	def __init__(self, i, o = None):
		'''Create a fake socket object.
		@param i: input file.
		@param o: output file.
		'''
		self._i = i
		self._o = o if o is not None else i
	def close(self):
		'''Close the fake socket object.
		@return None.'''
		pass
	def sendall(self, data):
		'''Send data to fake socket object.
		@return None.'''
		while len(data) > 0:
			fd = self._o if isinstance(self._o, int) else self._o.fileno()
			ret = os.write(fd, data)
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

def wrap(i, o = None): # {{{
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
	def __init__(self, address, tls = False, disconnect_cb = None, remote = None, connections = None): # {{{
		'''Create a connection.
		@param address: connection target.  This is a unix domain
		socket if there is a / in it.  If it is not a unix domain
		socket, it is a port number or service name, optionally
		prefixed with a hostname and a :.  If no hostname is present,
		localhost is used.
		@param tls: whether TLS encryption should be used.  Can be True
		or False, or None to try encryption first and fall back to
		unencrypted.  Setting this to None may trigger an error message
		and may fail to connect to unencrypted sockets due to the
		encryption handshake not returning.
		@param disconnect_cb: callback function for when the connection
		is lost.
		@param remote: For internal use only.
		@param connections: For internal use only.
		'''
		## read only variable which indicates whether TLS encryption is used on this socket.
		self.tls = tls
		## remote end of the network connection.
		self.remote = remote
		## connections set where this socket is registered.
		self.connections = connections
		if self.connections is not None:
			self.connections.add(self)
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
		if self.connections is not None:
			self.connections.remove(self)
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
		try:
			self.socket.sendall(data)
		except BrokenPipeError:
			self.close()
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
	def rawread(self, callback, error = None): # {{{
		'''Register function to be called when data is ready for reading.
		The function will be called when data is ready.  The callback
		must read the function or call unread(), or it will be called
		again after returning.
		@param callback: function to be called when data can be read.
		@param error: function to be called if there is an error on the socket.
		@return The data that was remaining in the line buffer, if any.
		'''
		if self.socket is None:
			return b''
		ret = self.unread()
		self._callback = (callback, None)
		self._event = add_read(self.socket, callback, error)
		return ret
	# }}}
	def read(self, callback, error = None, maxsize = 4096): # {{{
		'''Register function to be called when data is received.
		When data is available, read it and call this function.  The
		data that was remaining in the line buffer, if any, is sent to
		the callback immediately.
		@param callback: function to call when data is available.  The
		data is passed as a parameter.
		@param error: function to be called if there is an error on the
		socket.
		@param maxsize: buffer size that is used for the recv call.
		@return None.
		'''
		if self.socket is None:
			return b''
		first = self.unread()
		self._maxsize = maxsize
		self._callback = (callback, False)
		def cb():
			data = self.recv(self._maxsize)
			#log('network read %d bytes' % len(data))
			if not self._event:
				return False
			callback(data)
			return True
		self._event = add_read(self.socket, cb, error)
		if first:
			callback(first)
	# }}}
	def readlines(self, callback, error = None, maxsize = 4096): # {{{
		'''Buffer incoming data until a line is received, then call a function.
		When a newline is received, all data up to that point is
		decoded as an utf-8 string and passed to the callback.
		@param callback: function that is called when a line is
		received.  The line is passed as a str parameter.
		@param error: function that is called when there is an error on
		the socket.
		@param maxsize: used for the recv calls that are made.  The
		returned data accumulates until a newline is received; this is
		not a limit on the line length.
		@return None.
		'''
		if self.socket is None:
			return
		self._linebuffer = self.unread()
		self._maxsize = maxsize
		self._callback = (callback, True)
		self._event = add_read(self.socket, self._line_cb, error)
	# }}}
	def _line_cb(self): # {{{
		self._linebuffer += self.recv(self._maxsize)
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
		return True
	# }}}
	def unread(self): # {{{
		'''Cancel a read() or rawread() callback.
		Cancel any read callback.
		@return Bytes left in the line buffer, if any.  The line buffer
			is cleared.
		'''
		if self._event:
			try:
				remove_read(self._event)
			except ValueError:
				# The function already returned False.
				pass
			self._event = None
		ret = self._linebuffer
		self._linebuffer = b''
		return ret
	# }}}
# }}}

class Server: # {{{
	'''Listen on a network port and accept connections.'''
	def __init__(self, port, obj, address = '', backlog = 5, tls = False, disconnect_cb = None):
		'''Start a server.
		@param port: Port to listen on.  Can be a unix domain socket,
			or a numerical port, or a service name.
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
		## Disconnect handler, to be used for new sockets.
		self.disconnect_cb = disconnect_cb
		if isinstance(port, str) and '/' in port:
			# Unix socket.
			# TLS is ignored for these sockets.
			self.tls = False
			self._socket = socket.socket(socket.AF_UNIX)
			self._socket.bind(port)
			self.port = port
			self._socket.listen(backlog)
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
		self._event = add_read(self._socket, lambda: self._cb(False), lambda: self._cb(False))
		if self.ipv6:
			self._event = add_read(self._socket6, lambda: self._cb(True), lambda: self._cb(True))
	def _cb(self, is_ipv6):
		if is_ipv6:
			new_socket = self._socket6.accept()
		else:
			new_socket = self._socket.accept()
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
		s = Socket(new_socket[0], remote = new_socket[1], disconnect_cb = self.disconnect_cb, connections = self.connections)
		self._obj(s)
		return True
	def close(self):
		'''Stop the server.
		@return None.
		'''
		self._socket.close()
		self._socket = None
		if self.ipv6:
			self._socket6.close()
			self._socket6 = None
		if isinstance(self.port, str) and '/' in self.port:
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

_timeouts = []
_abort = False
def _handle_timeouts(): # {{{
	now = time.time()
	while not _abort and len(_timeouts) > 0 and _timeouts[0][0] <= now:
		_timeouts.pop(0)[1]()
	if len(_timeouts) == 0:
		return float('inf')
	return _timeouts[0][0] - now
# }}}

_fds = [[], []]
def iteration(block = False): # {{{
	'''Do a single iteration of the main loop.
	@return None.'''
	# The documentation says timeout should be omitted, it doesn't mention making it None.
	t = _handle_timeouts()
	if not block:
		t = 0
	#log('do select with timeout %f' % t)
	if math.isinf(t):
		ret = select.select(_fds[0], _fds[1], _fds[0] + _fds[1])
	else:
		ret = select.select(_fds[0], _fds[1], _fds[0] + _fds[1], t)
	#log('select returned %s' % repr(ret))
	for f in ret[2]:
		if f not in _fds[0] and f not in _fds[1]:
			continue
		if not f.error():
			try:
				remove_read(f)
			except ValueError:
				# The connection was already closed.
				pass
		if _abort:
			return
	for f in ret[0]:
		if f not in _fds[0]:
			continue
		if not f.handle():
			try:
				remove_read(f)
			except ValueError:
				# The connection was already closed.
				pass
		if _abort:
			return
	for f in ret[1]:
		if f not in _fds[1]:
			continue
		if not f.handle():
			remove_write(f)
		if _abort:
			return
	_handle_timeouts()
# }}}

_running = False
_idle = []
def fgloop(): # {{{
	'''Wait for events and handle them.
	This function does not fork into the background like bgloop().
	@return None.
	'''
	global _running
	assert not _running
	_running = True
	try:
		while _running:
			iteration(len(_idle) == 0)
			if not _running:
				return False
			for i in _idle[:]:
				if not i():
					remove_idle(i)
				if not _running:
					break
	finally:
		_abort = False
	return False
# }}}

def bgloop(): # {{{
	'''Like fgloop, but forks to the background.
	Unlike fgloop(), this function does not support a timeout.
	If the environment variable NETWORK_NO_FORK is set, it will
	remain in the foreground.
	@return None.'''
	assert _running == False
	if os.getenv('NETWORK_NO_FORK') is None:
		if os.fork() != 0:
			sys.exit(0)
	else:
		log('Not backgrounding because NETWORK_NO_FORK is set\n')
	fgloop()
# }}}

def endloop(force = False): # {{{
	'''Stop a loop that was started with fgloop() or bgloop().
	@return None.
	'''
	global _running, _abort
	assert _running
	_running = False
	if force:
		_abort = True
# }}}

class _fd_wrap: # {{{
	def __init__(self, fd, cb, error):
		self.fd = fd
		self.handle = cb
		if error is not None:
			self.error = error
		else:
			self.error = self.default_error
	def fileno(self):
		if isinstance(self.fd, int):
			return self.fd
		else:
			return self.fd.fileno()
	def default_error(self):
		try:
			remove_read(self)
			log('Error returned from select; removed fd from read list')
		except:
			try:
				remove_write(self)
				log('Error returned from select; removed fd from write list')
			except:
				log('Error returned from select, but fd was not in read or write list')
# }}}

def add_read(fd, cb, error = None): # {{{
	_fds[0].append(_fd_wrap(fd, cb, error))
	#log('add read %s' % repr(_fds[0][-1]))
	return _fds[0][-1]
# }}}

def add_write(fd, cb, error = None): # {{{
	_fds[1].append(_fd_wrap(fd, cb, error))
	return _fds[1][-1]
# }}}

def add_timeout(abstime, cb): # {{{
	_timeouts.append([abstime, cb])
	ret = _timeouts[-1]
	_timeouts.sort()
	return ret
# }}}

def add_idle(cb): # {{{
	_idle.append(cb)
	return _idle[-1]
# }}}

def remove_read(handle): # {{{
	#log('remove read %s' % repr(handle))
	#traceback.print_stack()
	_fds[0].remove(handle)
# }}}

def remove_write(handle): # {{{
	_fds[1].remove(handle)
# }}}

def remove_timeout(handle): # {{{
	_timeouts.remove(handle)
# }}}

def remove_idle(handle): # {{{
	_idle.remove(handle)
# }}}
