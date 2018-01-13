#!/usr/bin/python
import sys
import socket
import ssl
import os, os.path
import threading
import base64
import fcntl
import traceback
import struct

from Crypto import Random

class CommunicationError(Exception):
	pass

class Connection(threading.Thread):
	def __init__(self, rawsock, remote_addr, server, conn_no):
		threading.Thread.__init__(self)
		self.rawsock=rawsock
		self.remote_addr=remote_addr
		self.server=server
		self.conn_no=conn_no

	_handshake1="passmate-server-protocol"
	_handshake2="passmate-protocol-server"

	def read_exactly(self, nbytes):
		ret=""
		while len(ret)!=nbytes:
			new=self.sock.read(nbytes-len(ret))
			if len(new)==0: # eof
				raise CommunicationError()
			else:
				ret+=new
		return ret

	def create(self):
		print "c#%i: request to create account"%self.conn_no
		auth_token=self.read_exactly(32)
		
		len_btoken=struct.unpack("!L", self.read_exactly(4))[0]
		if len_btoken>self.server.max_btoken_length:
			raise CommunicationError()
		btoken=self.read_exactly(len_btoken)
		print "c#%i: received btoken of length=%i"%(self.conn_no,len_btoken)
		
		account_no=Random.new().read(8)
		filename=os.path.join(self.server.storage_dir, "%s.spr"%base64.b16encode(account_no))
		fd=os.open(filename, os.O_WRONLY|os.O_EXCL|os.O_CREAT, 0600)
		fcntl.lockf(fd, fcntl.LOCK_EX)
		with os.fdopen(fd, "w") as f:
			f.write(auth_token)
			f.write(btoken)
			
		self.sock.write(account_no)
		print "c#%i: returned new account_no=%s"%(self.conn_no,base64.b16encode(account_no))

	def update(self):
		account_no=self.read_exactly(8)
		auth_token_received=self.read_exactly(32)

		print "c#%i: request to update account_no=%s"%(self.conn_no, base64.b16encode(account_no))
		
		filename=os.path.join(self.server.storage_dir, "%s.spr"%base64.b16encode(account_no))
		fd=os.open(filename, os.O_RDWR, 0600)
		fcntl.lockf(fd, fcntl.LOCK_EX)
		with os.fdopen(fd, "r+") as f:
			auth_token_stored=f.read(32)
			if auth_token_stored!=auth_token_received:
				raise CommunicationError()
			btoken_send=f.read()
			self.sock.write(struct.pack("!L", len(btoken_send)))
			self.sock.write(btoken_send)
			print "c#%i: sent btoken of length=%i"%(self.conn_no,len(btoken_send))
			
			len_btoken_recv=struct.unpack("!L", self.read_exactly(4))[0]
			if len_btoken_recv>self.server.max_btoken_length:
				raise CommunicationError()
			btoken_recv=self.read_exactly(len_btoken_recv)
			print "c#%i: received btoken of length=%i"%(self.conn_no,len_btoken_recv)
			
			f.seek(0)
			f.truncate(0)
			f.write(auth_token_stored)
			f.write(btoken_recv)
			
		self.sock.write(account_no)
		print "c#%i: returned existing account_no=%s"%(self.conn_no,base64.b16encode(account_no))
		
	def reset(self):
		account_no=self.read_exactly(8)
		auth_token_received=self.read_exactly(32)

		print "c#%i: request to reset account_no=%s"%(self.conn_no, base64.b16encode(account_no))
		
		filename=os.path.join(self.server.storage_dir, "%s.spr"%base64.b16encode(account_no))
		fd=os.open(filename, os.O_RDWR, 0600)
		fcntl.lockf(fd, fcntl.LOCK_EX)
		with os.fdopen(fd, "r+") as f:
			auth_token_stored=f.read(32)
			if auth_token_stored!=auth_token_received:
				raise CommunicationError()
			f.seek(0)
			f.truncate(0) # subsequent attempts to reset or update the file after we now release the lock will fail to authenticate, so they will fail :)
		os.unlink(filename)
		
		self.sock.write(account_no)
		print "c#%i: returned deleted account_no=%s"%(self.conn_no,base64.b16encode(account_no))

	def interact(self):
		if self.read_exactly(len(self._handshake1))!=self._handshake1:
			raise CommunicationError()
		self.sock.write(self._handshake2)
		self.sock.write(struct.pack("!HL", self.server.server_protocol_version, len(self.server.banner)))
		self.sock.write(self.server.banner)
		action=self.read_exactly(1)
		if action=='c':
			self.create()
		elif action=='u':
			self.update()
		elif action=='r':
			self.reset()
		else:
			raise CommunicationError()
		
		print "c#%i: successfully completed"%self.conn_no

	def run(self):
		self.sock = ssl.wrap_socket(self.rawsock, keyfile=self.server.key_file, 	certfile=self.server.ca_file, server_side=True)
		print "c#%i: connected to %s"%(self.conn_no, self.remote_addr)

		try:
			self.interact()
		except Exception as e:
			traceback.print_exc()
		finally:
			print "c#%i: cleaning up"%self.conn_no
			self.sock.shutdown(socket.SHUT_RDWR)
			self.sock.close()

class SyncServer:
	server_protocol_version=2 # 2 = no double encryption anymore. requires no server changes, but clients should not confuse version 1 btokens with version 2 btokens.
	max_btoken_length=2*1024*1024

	def __init__(self, ca_file, key_file, storage_dir, banner_file):
		self.ca_file=ca_file
		self.key_file=key_file
		self.storage_dir=storage_dir
		with open(banner_file, "r") as f:
			self.banner=f.read()
		

	def run(self):
		conn_counter=0
		bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		bindsocket.bind(('0.0.0.0', 29556))
		bindsocket.listen(5)

		while True:
			conn_counter+=1
			newsocket, fromaddr = bindsocket.accept()
			Connection(newsocket, fromaddr, self, conn_counter).start()
			

def main():
	if len(sys.argv)!=5:
		print "Usage: ./server.py CA_FILE KEY_FILE STORAGE_DIR BANNER_FILE"
		sys.exit(1)
	
	SyncServer(
		ca_file=sys.argv[1],
		key_file=sys.argv[2],
		storage_dir=sys.argv[3],
		banner_file=sys.argv[4]	
	).run()
	
if __name__=="__main__":
	main()
