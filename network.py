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
	pass
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

class Error (StandardError): # {{{
	pass
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
	def __init__ (self, address, remote = None):
		self.remote = remote
		if isinstance (address, socket.socket):
			self.socket = address
			return
		if isinstance (address, str) and '/' in address:
			# Unix socket.
			self.remote = address
			self.socket = socket.socket (socket.AF_UNIX)
			self.socket.connect (self.remote)
		elif have_avahi and isinstance (address, str) and '|' in address:
			# Avahi.
			ret = []
			info = address.split ('|')
			assert len (info) == 2
			if info[1] == '':
				count = [0]
			else:
				count = [int (info[1])]
			type = '_%s._tcp' % info[0]
			bus = dbus.SystemBus (mainloop = DBusGMainLoop ())
			server = dbus.Interface (bus.get_object (avahi.DBUS_NAME, '/'), 'org.freedesktop.Avahi.Server')
			browser = dbus.Interface (bus.get_object (avahi.DBUS_NAME, server.ServiceBrowserNew (avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, type, 'local', dbus.UInt32 (0))), avahi.DBUS_INTERFACE_SERVICE_BROWSER)
			def handle2 (*args):
				self.remote = (str (args[7]), int (args[8]))
				mainloop.quit ()
			def handle_error (*args):
				print ('avahi lookup error (ignored): %s' % args[0])
			def handle (interface, protocol, name, type, domain, flags):
				if count[0] == 0:
					server.ResolveService (interface, protocol, name, type, domain, avahi.PROTO_UNSPEC, dbus.UInt32 (0), reply_handler = handle2, error_handler = handle_error)
				count[0] -= 1
			browser.connect_to_signal ('ItemNew', handle)
			mainloop = glib.MainLoop ()
			mainloop.run ()
			self.socket = socket.create_connection (self.remote)
		else:
			if isinstance (address, str) and ':' in address:
				host, port = address.rsplit (':', 1)
			else:
				host, port = 'localhost', address
			self.remote = (host, lookup (port))
			self.socket = socket.create_connection (self.remote)
	def close (self):
		self.socket.close ()
		del self.socket
	def send (self, data):
		self.socket.sendall (data)
	def recv (self, maxsize = 4096):
		ret = self.socket.recv (maxsize)
		if len (ret) == 0:
			raise EOFError ('network connection closed')
		return ret
	def read (self, callback, maxsize = 4096):
		if have_glib:
			glib.io_add_watch (self.socket.fileno (), glib.IO_IN | glib.IO_PRI, lambda fd, cond: callback (self.recv (maxsize)))
	def rawread (self, callback):
		if have_glib:
			glib.io_add_watch (self.socket.fileno (), glib.IO_IN | glib.IO_PRI, lambda fd, cond: callback ())
# }}}

if have_glib:
	class Server: # {{{
		def __init__ (self, port, datacb, acceptcb = None, address = '', backlog = 5):
			'''Listen on a port and accept connections.'''
			self.group = None
			self.datacb = datacb
			self.acceptcb = acceptcb
			self.port = ''
			if isinstance (port, str) and '/' in port:
				# Unix socket.
				self.socket = socket.socket (socket.AF_UNIX)
				self.socket.bind (port)
				self.port = port
				self.socket.listen (backlog)
			elif have_avahi and isinstance (port, str) and '|' in port:
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
				bus = dbus.SystemBus ()
				server = dbus.Interface (bus.get_object (avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER), avahi.DBUS_INTERFACE_SERVER)
				self.group = dbus.Interface (bus.get_object (avahi.DBUS_NAME, server.EntryGroupNew ()), avahi.DBUS_INTERFACE_ENTRY_GROUP)
				self.group.AddService (avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, dbus.UInt32 (0), info[1], '_%s._tcp' % info[0], '', '', dbus.UInt16 (self.socket.getsockname ()[1]), '')
				self.group.Commit ()
			else:
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
				self.port = port
			fd = self.socket.fileno ()
			glib.io_add_watch (fd, glib.IO_IN | glib.IO_PRI, self._cb)
		def _cb (self, fd, cond):
			new_socket = self.socket.accept ()
			s = Socket (new_socket[0], new_socket[1])
			if self.acceptcb is not None:
				self.acceptcb (s)
			if self.datacb is not None:
				s.read (lambda data: self.datacb (s, data) or True)
			return True
		def close (self):
			if self.group:
				self.group.Reset ()
				self.group = None
			self.socket.close ()
			self.socket = None
			if '/' in self.port:
				os.remove (self.port)
			self.port = ''
		def __del__ (self):
			if self.socket is not None:
				self.close ()
	# }}}

class RPCSocket (object): # {{{
	def __init__ (self, address, object = None, disconnected = None):
		self._object = object
		self._disconnected = disconnected
		if isinstance (address, Socket):
			self._socket = address
		else:
			self._socket = Socket (address, None)
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
			print 'exception: %s\n%s' % (v[0], '\n'.join ('\t%s:%d' % (x[0], x[1]) for x in v[1]))
			raise v[0]
		else:
			return v
	def _send (self, data):
		d = pickle.dumps (data)
		self._socket.send ('%20d' % len (d) + d)
	def _recv (self):
		l = int (self._socket.recv (20))
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

class RPCServer: # {{{
	def __init__ (self, port, factory, disconnected = None, address = '0.0.0.0', backlog = 5):
		self.factory = factory
		self.disconnected = disconnected
		self.server = Server (port, None, self._accept, address, backlog)
	def close (self):
		self.server.close ()
	def _accept (self, socket):
		rpc = RPCSocket (socket, None)
		rpc._object = self.factory (rpc)
		if self.disconnected is not None:
			rpc._disconnected = lambda: self.disconnected (rpc)
# }}}

def bgloop (): # {{{
	if os.fork () != 0:
		sys.exit (0)
	glib.MainLoop ().run ()
# }}}
