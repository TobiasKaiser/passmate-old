from backend import Storage
import base64
import struct
import socket
import ssl
import tempfile
import string

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto import Random

def crc16(data): # CRC-CCITT / http://stackoverflow.com/questions/10564491/function-to-calculate-a-crc16-checksum
	crc = 0xFFFF
	for byte in data:
		x=(crc>>8) ^ ord(byte)
		x ^= x >> 4
		crc=(crc<<8) ^ (x<<12) ^ (x<<5) ^ (x)
		crc &= 0xffff
	return crc

# Key format:
# 972833-867473-888541-975566-332200-641368-206880-972833-867473-888541-975566-332200-641368-206880
# aaaaaa-aaaaaa-aaaakk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkkkkk-kkcccc

def pack_key(account_no, key):
	if len(account_no)!=8:
		raise ValueError("Illegal account no length")
	if len(key)!=32:
		raise ValueError("Illegal key length")
	data=account_no+key+struct.pack(">H", crc16(account_no+key))
	b16data=base64.b16encode(data)
	x=map(lambda i: b16data[i:i+6], range(0, len(b16data), 6))
	return string.join(x, '-')

def unpack_key(key):
	data=base64.b16decode(filter(lambda x: x in string.hexdigits, key))
	if len(data)!=42:
		raise SyncError(SyncError.ILLEGAL_KEY)
	account_no=data[0:8]
	key=data[8:40]
	checksum=data[40:42]
	if crc16(account_no+key)!=struct.unpack(">H", checksum)[0]:
		raise SyncError(SyncError.ILLEGAL_KEY)
	return account_no, key
	
class SyncError(Exception):
	GENERIC=0
	SERVER_ERROR=1
	ALREADY_ASSOCIATED=2
	NOT_ASSOCIATED=3
	NOT_IMPLEMENTED=4
	SERVER_PROTOCOL_VERSION_MISMATCH=4
	ILLEGAL_KEY=5
	ILLEGAL_BTOKEN=6
	SERVER_ERROR=7
	UNEXPECTED_COMMUNICATION_END=8
	def __init__(self, number, message=""):
		super(SyncError, self).__init__(message)
		self.number = number

class SyncableStorage(Storage):
	_handshake1="passmate-server-protocol"
	_handshake2="passmate-protocol-server"

	def all_keys(self, key):
		aes_data_key=HMAC.new(key, "aes_data_key", SHA256).digest()
		hmac_key=HMAC.new(key, "mac_key", SHA256).digest()
		auth_token=HMAC.new(key, "auth_token", SHA256).digest()
		return aes_data_key, hmac_key, auth_token
	
	def get_btoken(self, key):
		aes_data_key, hmac_key, _=self.all_keys(key)
		iv = Random.new().read(AES.block_size)
		
		cleartext=self.encrypt_data_without_config()
		
		ciphertext = AES.new(aes_data_key, AES.MODE_CBC, iv).encrypt(cleartext)
		hmac = HMAC.new(hmac_key, ciphertext, SHA256).digest()
		
		# IV is 16 bytes, hmac is 32 bytes, ciphertext is rest
		return iv+hmac+ciphertext
	
	def put_btoken(self, btoken, key):
		if len(btoken)<(4096+128+32+16): # 16 byte IV, 32 byte HMAC, 128 byte scrypt header, data in multiple of 4096
			raise SyncError(SyncError.ILLEGAL_BTOKEN)
		
		aes_data_key, hmac_key, _=self.all_keys(key)
		
		iv, hmac_received, ciphertext=btoken[0:16], btoken[16:48], btoken[48:]
		
		hmac_calculated = HMAC.new(hmac_key, ciphertext, SHA256).digest()
		if hmac_received!=hmac_calculated:
			raise SyncError(SyncError.ILLEGAL_BTOKEN)
		
		cleartext=AES.new(aes_data_key, AES.MODE_CBC, iv).decrypt(ciphertext)
		return self.decrypt_and_merge_data_without_config(cleartext)
	
	def sync_associated(self):
		return "sync_host" in self.config
	
	def read_exactly(self, sock, nbytes):
		ret=""
		while len(ret)!=nbytes:
			new=sock.read(nbytes-len(ret))
			if len(new)==0: # eof
				raise SyncError(SyncError.UNEXPECTED_COMMUNICATION_END)
			else:
				ret+=new
		return ret
	
	def connect_to_sync_server(self, hostname=None, own_ca_data=None):
		if not hostname:
			hostname=self.config["sync_host"]
			if not own_ca_data: # only if hostname is not set!
				own_ca_data=base64.b64decode(self.config["own_ca_data"]) if self.config["own_ca_data"] else None
	
		sock_raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		
		ca_certs_filename="/etc/ssl/certs/ca-certificates.crt"
		if own_ca_data:
			tf=tempfile.NamedTemporaryFile()
			tf.write(own_ca_data)
			tf.flush()
			ca_certs_filename=tf.name
		
		sock = ssl.wrap_socket(sock_raw, ca_certs=ca_certs_filename, cert_reqs=ssl.CERT_REQUIRED)
		try:
			sock.connect((hostname, 29556))
			
			if own_ca_data:
				tf.close() # also deletes the temporary file
		
			sock.write(self._handshake1)
			if self.read_exactly(sock, len(self._handshake2))!=self._handshake2:
				raise SyncError(SyncError.SERVER_ERROR)
		
			server_protocol_version, banner_length=struct.unpack("!HL", self.read_exactly(sock, 6))
			banner=self.read_exactly(sock, banner_length)
		
			
		except:
			sock.close()
			raise
		return sock, server_protocol_version, banner
		
		
	def sync_setup(self, hostname, key, own_ca_filename=None):
		if self.sync_associated():
			raise SyncError(SyncError.ALREADY_ASSOCIATED)
	
		if own_ca_filename:
			with open(own_ca_filename, 'r') as f:
				own_ca_data=f.read()
		else:
			own_ca_data=None
		
	
		if key:
			self.config["sync_host"]=hostname
			self.config["sync_key"]=key
			self.config["own_ca_data"]=base64.b64encode(own_ca_data) if own_ca_data else None
			try:
				return self.sync()
			except:
				self.config.pop("sync_host")
				self.config.pop("sync_key")
				self.config.pop("own_ca_data")
				raise
		else:
			return self.sync_setup_new_account(hostname, key, own_ca_data)
		
	def sync_setup_new_account(self, hostname, key, own_ca_data):
		msg=""
		key=Random.new().read(256/8)
		_, _, auth_token=self.all_keys(key)
	
		sock, server_protocol_version, banner=self.connect_to_sync_server(hostname, own_ca_data)
		try:
			if server_protocol_version!=1:
				raise SyncError(SyncError.SERVER_PROTOCOL_VERSION_MISMATCH)
			msg+="Remote reports:\n"+banner
		
			btoken=self.get_btoken(key)
			sock.write('c' + auth_token + struct.pack("!L", len(btoken)))
			sock.write(btoken)
			
			account_no=struct.unpack("!8s",self.read_exactly(sock, 8))[0]
			
			if account_no=="\0\0\0\0\0\0\0\0":
				raise SyncError(SyncError.SERVER_ERROR)
		finally:
			sock.close()
			
		self.config["sync_host"]=hostname
		self.config["sync_key"]=pack_key(account_no, key)
		self.config["own_ca_data"]=base64.b64encode(own_ca_data) if own_ca_data else None
		self.changed=True
		msg+="success!\n"
		return msg
	
	def sync_delete_from_server(self):
		msg=""
		account_no, key = unpack_key(self.config["sync_key"])
		_, _, auth_token=self.all_keys(key)
		
		sock, server_protocol_version, banner=self.connect_to_sync_server()
		try:
			if server_protocol_version!=1:
				raise SyncError(SyncError.SERVER_PROTOCOL_VERSION_MISMATCH)
			msg+="Remote reports:\n"+banner
		
			sock.write('r' + account_no + auth_token)
			
			account_no_recv=struct.unpack("!8s",self.read_exactly(sock, 8))[0]
			
			if account_no_recv!=account_no:
				raise SyncError(SyncError.SERVER_ERROR)
		finally:
			sock.close()
	
		return msg
	
	def sync(self):
		if not self.sync_associated():
			raise SyncError(SyncError.NOT_ASSOCIATED)
		msg=""

		account_no, key = unpack_key(self.config["sync_key"])
		_, _, auth_token=self.all_keys(key)
		
		sock, server_protocol_version, banner=self.connect_to_sync_server()
		try:
			if server_protocol_version!=1:
				raise SyncError(SyncError.SERVER_PROTOCOL_VERSION_MISMATCH)
			msg+="Remote reports:\n"+banner
		
			sock.write('u' + account_no + auth_token)
			
			len_btoken_recv=struct.unpack("!L", self.read_exactly(sock, 4))[0]
			btoken_recv=self.read_exactly(sock, len_btoken_recv)
			
			report=self.put_btoken(btoken_recv, key)
			msg+="="*64+'\n'
			if len(report)>0:
				msg+=string.join(map(lambda x: x.lineformat(), report), "\n")
			else:
				msg+="All records up-to-date."
			btoken_send=self.get_btoken(key)
			sock.write(struct.pack("!L", len(btoken_send)))
			sock.write(btoken_send)
			
			account_no_recv=struct.unpack("!8s",self.read_exactly(sock, 8))[0]
			
			if account_no_recv!=account_no:
				raise SyncError(SyncError.SERVER_ERROR)
		finally:
			sock.close()
		
		return msg
	
	def sync_reset(self, delete_from_server):
		if not self.sync_associated():
			raise SyncError(SyncError.NOT_ASSOCIATED)
		msg=""
		
		if delete_from_server:
			msg+=self.sync_delete_from_server()
		
		self.config.pop("sync_host")
		self.config.pop("sync_key")
		self.config.pop("own_ca_data")
		
		return msg
	
	def sync_showkey(self):
		if not self.sync_associated():
			raise SyncError(SyncError.NOT_ASSOCIATED)
		
		return self.config["sync_key"]
