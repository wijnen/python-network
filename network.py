# Python module for easy networking.
# vim: set fileencoding=utf-8 foldmethod=marker :

# {{{ Copyright 2012 Bas Wijnen <wijnen@debian.org>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
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
import pickle
import socket
import select
import re
import time
import xdgbasedir
try:
	import ssl
	have_ssl = True
except:
	have_ssl = False
try:
	import glib
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
# - rpc interface
#   - set up server with object
#   - connect to server with object
#   - call function (incl. return)

# implementation:
# - Server: listener, creating Sockets on accept
# - Socket: used for connection; symmetric
# - RPCServer, RPCSocket: wrapper with RPC interface
# }}}

def log (message): # {{{
	t = time.strftime ('%c %Z %z')
	sys.stderr.write (''.join (['%s: %s\n' % (t, m) for m in message.split ('\n')]))
# }}}

def lookup (service): # {{{
	if isinstance (service, int):
		return service
	try:
		return socket.getservbyname (service)
	except socket.error:
		pass
	return int (service)
# }}}

class Socket: # {{{
	def __init__ (self, address, tls = None, disconnect_cb = None, remote = None): # {{{
		self.tls = tls
		self.remote = remote
		self._disconnect_cb = disconnect_cb
		self.event = None
		self._linebuffer = ''
		if isinstance (address, socket.socket):
			self.socket = address
			return
		if isinstance (address, str) and '/' in address:
			# Unix socket.
			# TLS is ignored for those.
			self.remote = address
			self.socket = socket.socket (socket.AF_UNIX)
			self.socket.connect (self.remote)
		elif have_avahi and isinstance (address, str) and '|' in address:
			# Avahi.
			ret = []
			found = [False]
			info = address.split ('|')
			assert len (info) == 2
			regexp = re.compile (info[1])
			type = '_%s._tcp' % info[0]
			bus = dbus.SystemBus (mainloop = DBusGMainLoop ())
			server = dbus.Interface (bus.get_object (avahi.DBUS_NAME, '/'), 'org.freedesktop.Avahi.Server')
			browser = dbus.Interface (bus.get_object (avahi.DBUS_NAME, server.ServiceBrowserNew (avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, type, 'local', dbus.UInt32 (0))), avahi.DBUS_INTERFACE_SERVICE_BROWSER)
			def handle2 (*args):
				self.remote = (str (args[5]), int (args[8]))
				mainloop.quit ()
			def handle_error (*args):
				log ('avahi lookup error (ignored): %s' % args[0])
			def handle (interface, protocol, name, type, domain, flags):
				if found[0]:
					return
				if regexp.match (name):
					found[0] = True
					server.ResolveService (interface, protocol, name, type, domain, avahi.PROTO_UNSPEC, dbus.UInt32 (0), reply_handler = handle2, error_handler = handle_error)
			def handle_eof ():
				if found[0]:
					return
				self.remote = None
				mainloop.quit ()
			browser.connect_to_signal ('ItemNew', handle)
			browser.connect_to_signal('AllForNow', handle_eof)
			browser.connect_to_signal('Failure', handle_eof)
			mainloop = glib.MainLoop ()
			mainloop.run ()
			if self.remote is not None:
				self.setup_connection ()
			else:
				raise EOFError ('Avahi service not found')
		else:
			if isinstance (address, str) and ':' in address:
				host, port = address.rsplit (':', 1)
			else:
				host, port = 'localhost', address
			self.remote = (host, lookup (port))
			#log ('remote %s' % str (self.remote))
			self.setup_connection ()
	# }}}
	def setup_connection (self): # {{{
		self.socket = socket.create_connection (self.remote)
		if self.tls is None:
			try:
				assert have_ssl
				self.socket = ssl.wrap_socket (self.socket, ssl_version = ssl.PROTOCOL_TLSv1)
			except:
				self.socket = socket.create_connection (self.remote)
		elif self.tls is True:
			try:
				assert have_ssl
				self.socket = ssl.wrap_socket (self.socket, ssl_version = ssl.PROTOCOL_TLSv1)
			except ssl.SSLError, e:
				raise TypeError ('Socket does not seem to support TLS: ' + str (e))
	# }}}
	def disconnect_cb (self, disconnect_cb): # {{{
		self._disconnect_cb = disconnect_cb
	# }}}
	def close (self): # {{{
		if not self.socket:
			return
		data = self.unread ()
		self.socket.close ()
		self.socket = None
		if self._disconnect_cb:
			return self._disconnect_cb (data)
		return data
	# }}}
	def send (self, data): # {{{
		if self.socket is None:
			return
		#print 'sending %s' % repr (data)
		self.socket.sendall (data)
	# }}}
	def recv (self, maxsize = 4096): # {{{
		if self.socket is None:
			return ''
		ret = ''
		try:
			ret = self.socket.recv (maxsize)
			if hasattr (self.socket, 'pending'):
				while self.socket.pending ():
					ret += self.socket.recv (maxsize)
		except:
			log ('Error reading from socket: %s' % sys.exc_value)
			self.close ()
			return ret
		if len (ret) == 0:
			ret = self.close ()
			if not self._disconnect_cb:
				raise EOFError ('network connection closed')
		return ret
	# }}}
	def rawread (self, callback): # {{{
		assert have_glib
		if self.socket is None:
			return ''
		ret = self.unread ()
		self.callback = (callback, None)
		self.event = glib.io_add_watch (self.socket.fileno (), glib.IO_IN | glib.IO_PRI, lambda fd, cond: (callback () or True))
		return ret
	# }}}
	def read (self, callback, maxsize = 4096): # {{{
		assert have_glib
		if self.socket is None:
			return ''
		first = self.unread ()
		self.maxsize = maxsize
		self.callback = (callback, False)
		def cb (fd, cond):
			data = self.recv (self.maxsize)
			#print ('network read %d bytes' % len (data))
			if not self.event:
				#print ('stopping')
				return False
			callback (data)
			return True
		self.event = glib.io_add_watch (self.socket.fileno (), glib.IO_IN | glib.IO_PRI, cb)
		if first:
			callback (first)
	# }}}
	def readlines (self, callback, maxsize = 4096): # {{{
		assert have_glib
		if self.socket is None:
			return
		self._linebuffer = self.unread ()
		self.maxsize = maxsize
		self.callback = (callback, True)
		self.event = glib.io_add_watch (self.socket.fileno (), glib.IO_IN | glib.IO_PRI, lambda fd, cond: (self._line_cb () or True))
	# }}}
	def _line_cb (self): # {{{
		self._linebuffer += self.recv (self.maxsize)
		while '\n' in self._linebuffer and self.event:
			assert self.callback[1] is not None	# Going directly from readlines() to rawread() is not allowed.
			if self.callback[1]:
				line, self._linebuffer = self._linebuffer.split ('\n', 1)
				self.callback[0] (line)
			else:
				data = self._linebuffer
				self._linebuffer = ''
				self.callback[0] (self._linebuffer)
	# }}}
	def unread (self): # {{{
		if self.event:
			glib.source_remove (self.event)
			self.event = None
		ret = self._linebuffer
		self._linebuffer = ''
		return ret
	# }}}
# }}}

class RPCSocket (object): # {{{
	def __init__ (self, address, object = None, tls = True, disconnected = None):
		self._object = object
		self._disconnected = disconnected
		if isinstance (address, Socket):
			self._socket = address
		else:
			self._socket = Socket (address, tls)
		self._socket.rawread (self._cb)
	def __getattr__ (self, attr):
		if attr == '__methods__':
			return self._call ('__methods__', [], {})
		ret = lambda *arg, **karg: self._call (attr, arg, karg)
		ret.__doc__ = self._call ('__doc__', [attr], {})
		return ret
	def _call (self, attr, arg, karg):
		self._send ((attr, arg, karg))
		while True:
			ret = self._recv ()
			if len (ret) == 2:
				r, v = ret
				break
			self._handle_recv (ret)
		if r == 'E':
			log ('exception: %s\n%s' % (v[0], '\n'.join ('\t%s:%d' % (x[0], x[1]) for x in v[1])))
			raise v[0]
		else:
			return v
	def _send (self, data):
		d = pickle.dumps (data)
		self._socket.send ('%20d' % len (d) + d)
	def _recv (self):
		d = self._socket.recv (20)
		if len (d) == 0:
			raise EOFError ("EOF at start of frame")
		l = int (d)
		data = ''
		while len (data) < l:
			data += self._socket.recv (l - len (data))
		return pickle.loads (data)
	def _cb (self):
		try:
			data = self._recv ()
		except EOFError:
			if self._disconnected:
				self._disconnected ()
			return False
		self._handle_recv (data)
		return True
	def _handle_recv (self, data):
		attr, a, ka = data
		try:
			if attr == '__methods__':
				ret = [x for x in dir (self._object) if not x.startswith ('_') and callable (getattr (self._object, x))]
			elif attr == '__doc__':
				ret = getattr (self._object, a[0]).__doc__
			else:
				assert attr != '' and attr[0] != '_'
				ret = getattr (self._object, attr) (*a, **ka)
			self._send (('R', ret))
		except:
			t = sys.exc_traceback
			tb = []
			while t:
				tb.append ((t.tb_frame.f_code.co_filename, t.tb_lineno))
				t = t.tb_next
			self._send (('E', (sys.exc_value, tb)))
# }}}

if have_glib:	# {{{
	class Server: # {{{
		def __init__ (self, port, obj, address = '', backlog = 5, tls = None, disconnect_cb = None):
			'''Listen on a port and accept connections.  Set tls to a key+certificate file to use tls.'''
			self._disconnect_cb = disconnect_cb
			self.group = None
			self.obj = obj
			self.port = ''
			self.ipv6 = False
			self.socket = None
			self.tls = tls
			self.connections = set ()
			if isinstance (port, str) and '/' in port:
				# Unix socket.
				# TLS is ignored for these sockets.
				self.tls = False
				self.socket = socket.socket (socket.AF_UNIX)
				self.socket.bind (port)
				self.port = port
				self.socket.listen (backlog)
			elif have_avahi and isinstance (port, str) and '|' in port:
				self._tls_init ()
				self.socket = socket.socket ()
				self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				if address == '':
					self.socket6 = socket.socket (socket.AF_INET6)
					self.socket6.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				info = port.split ('|')
				self.port = port
				if len (info) > 2:
					self.socket.bind ((address, lookup (info[2])))
				self.socket.listen (backlog)
				if address == '':
					p = self.socket.getsockname ()[1]
					self.socket6.bind (('::1', p))
					self.socket6.listen (backlog)
					self.ipv6 = True
				bus = dbus.SystemBus ()
				server = dbus.Interface (bus.get_object (avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER), avahi.DBUS_INTERFACE_SERVER)
				self.group = dbus.Interface (bus.get_object (avahi.DBUS_NAME, server.EntryGroupNew ()), avahi.DBUS_INTERFACE_ENTRY_GROUP)
				self.group.AddService (avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, dbus.UInt32 (0), info[1], '_%s._tcp' % info[0], '', '', dbus.UInt16 (self.socket.getsockname ()[1]), '')
				self.group.Commit ()
			else:
				self._tls_init ()
				port = lookup (port)
				self.socket = socket.socket ()
				self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				self.socket.bind ((address, port))
				self.socket.listen (backlog)
				if address == '':
					self.socket6 = socket.socket (socket.AF_INET6)
					self.socket6.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
					self.socket6.bind (('::1', port))
					self.socket6.listen (backlog)
					self.ipv6 = True
				self.port = port
			fd = self.socket.fileno ()
			glib.io_add_watch (fd, glib.IO_IN | glib.IO_PRI, self._cb)
			if self.ipv6:
				fd = self.socket6.fileno ()
				glib.io_add_watch (fd, glib.IO_IN | glib.IO_PRI, self._cb)
		def set_disconnect_cb (self, disconnect_cb):
			self._disconnect_cb = disconnect_cb
		def _cb (self, fd, cond):
			if fd == self.socket.fileno ():
				new_socket = self.socket.accept ()
			else:
				new_socket = self.socket6.accept ()
			if self.tls:
				assert have_ssl
				try:
					new_socket = (ssl.wrap_socket (new_socket[0], ssl_version = ssl.PROTOCOL_TLSv1, server_side = True, certfile = self.tls_cert, keyfile = self.tls_key), new_socket[1])
				except ssl.SSLError, e:
					log ('Rejecting (non-TLS?) connection for %s: %s' % (repr (new_socket[1]), str (e)))
					return True
			s = Socket (new_socket[0], remote = new_socket[1], disconnect_cb = lambda data: self._handle_disconnect (s, data))
			self.connections.add (s)
			self.obj (s)
			return True
		def _handle_disconnect (self, socket, data):
			self.connections.remove (socket)
			if self._disconnect_cb:
				return self._disconnect_cb (data)
			return data
		def close (self):
			if self.group:
				self.group.Reset ()
				self.group = None
			self.socket.close ()
			self.socket = None
			if self.ipv6:
				self.socket6.close ()
				self.socket6 = None
			if '/' in self.port:
				os.remove (self.port)
			self.port = ''
		def __del__ (self):
			if self.socket is not None:
				self.close ()
		def _tls_init (self):
			# Set up members for using tls, if requested.
			self.tls = xdgbasedir.config_load (None, 'network', {'tls': ''}, os.getenv ('NETWORK_OPTS', '').split ())['tls']
			if self.tls == '':
				self.tls = socket.getfqdn ()
			elif self.tls == '.':
				self.tls = False
				return
			# Use tls.
			fc = xdgbasedir.data_files_read (os.path.join ('certs', self.tls + os.extsep + 'pem'), 'network')
			fk = xdgbasedir.data_files_read (os.path.join ('private', self.tls + os.extsep + 'key'), 'network')
			if len (fc) == 0 or len (fk) == 0:
				# Create new self-signed certificate.
				path = xdgbasedir.data_filename_write ('certs', False, 'network')
				if not os.path.exists (path):
					os.makedirs (path)
				path = xdgbasedir.data_filename_write ('private', False, 'network')
				if not os.path.exists (path):
					os.makedirs (path, 0700)
				os.system ('openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -subj "/CN=%s" -keyout "%s" -out "%s"' % (self.tls, xdgbasedir.data_filename_write (os.path.join ('private', self.tls + os.extsep + 'key'), False, 'network'), xdgbasedir.data_filename_write (os.path.join ('certs', self.tls + os.extsep + 'pem'), False, 'network')))
				fc = xdgbasedir.data_files_read (os.path.join ('certs', self.tls + os.extsep + 'pem'), 'network')
				fk = xdgbasedir.data_files_read (os.path.join ('private', self.tls + os.extsep + 'key'), 'network')
			self.tls_cert = fc[0]
			self.tls_key = fk[0]
	# }}}

	class RPCServer: # {{{
		def __init__ (self, port, factory, disconnected = None, address = '', backlog = 5, tls = None):
			self.tls = tls
			self.factory = factory
			self.disconnected = disconnected
			self.server = Server (port, self._accept, address, backlog, None)
		def close (self):
			self.server.close ()
		def _accept (self, socket):
			rpc = RPCSocket (socket, None, self.tls)
			rpc._object = self.factory (rpc)
			if self.disconnected is not None:
				rpc._disconnected = lambda: self.disconnected (rpc)
	# }}}

	loop = None
	def fgloop (): # {{{
		global loop
		assert loop is None
		loop = glib.MainLoop ()
		loop.run ()
	# }}}

	def bgloop (): # {{{
		if os.getenv ('NETWORK_NO_FORK') is None:
			if os.fork () != 0:
				sys.exit (0)
		else:
			log ('Not backgrounding because NETWORK_NO_FORK is set\n')
		fgloop ()
	# }}}

	def endloop (): # {{{
		global loop
		assert loop is not None
		loop.quit ()
		loop = None
	# }}}

	def iteration (): # {{{
		glib.MainContext ().iteration (False)
	# }}}
# }}}
