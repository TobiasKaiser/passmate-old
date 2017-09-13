
#include <cstdio>
#include <string>

#include <arpa/inet.h>

#include "SyncableStorage.hpp"

using namespace std;


// CRC-CCITT / http://stackoverflow.com/questions/10564491/function-to-calculate-a-crc16-checksum
uint16_t SyncableStorage::crc16(const uint8_t *data, size_t len)
{
	uint16_t crc = 0xFFFF;

	size_t i;
	for(i=0;i<len;i++) {
		uint16_t x = (crc>>8) ^ data[i];
		crc = (crc<<8) ^ (x<<12) ^ (x<<5) ^ (x);

		crc &= 0xFFFF; // not necessary ;P
	}

	return crc;
}


//def pack_key(account_no, key):
//	if len(account_no)!=8:
//		raise ValueError("Illegal account no length")
//	if len(key)!=32:
//		raise ValueError("Illegal key length")
//	data=account_no+key+struct.pack(">H", crc16(account_no+key))
//	b16data=base64.b16encode(data)
//	x=map(lambda i: b16data[i:i+6], range(0, len(b16data), 6))
//	return string.join(x, '-')


// writes key and account no by reference
void SyncableStorage::unpack_key(const string &key, string &account_no, string &enckey)
{
	if(key.length()!= 14*6 + 13) {
		throw Storage::Exception(Storage::Exception::SYNC_ILLEGAL_KEY);
	}

	uint8_t data[42 + 1];

	int i;
	for(i=0;i<14;i++) {
		unsigned int a=0, b=0, c=0;

		if(sscanf(key.c_str() + 7*i, "%02X%02X%02X", &a, &b, &c) != 3) {
			throw Storage::Exception(Storage::Exception::SYNC_ILLEGAL_KEY);
		}

		data[3*i + 0] = a;
		data[3*i + 1] = b;
		data[3*i + 2] = c;

		if(i!=13) {
			if(key[7*i+6]!='-') {
				throw Storage::Exception(Storage::Exception::SYNC_ILLEGAL_KEY);	
			}
		}
	}

	data[43] = '\0';

	uint16_t checksum = crc16(data, 32 + 8);

	uint16_t checksum_be = htons(checksum);

	if(memcmp(&checksum_be, data+40, 2)!=0) {
		throw Storage::Exception(Storage::Exception::SYNC_ILLEGAL_KEY);
	}

	string data_str( (char*)data);

	account_no = data_str.substr(0, 8);

	enckey = data_str.substr(8, 32);

}

//def unpack_key(key):
//	data=base64.b16decode(filter(lambda x: x in string.hexdigits, key))
//	if len(data)!=42:
//		raise SyncError(SyncError.ILLEGAL_KEY)
//	account_no=data[0:8]
//	key=data[8:40]
//	checksum=data[40:42]
//	if crc16(account_no+key)!=struct.unpack(">H", checksum)[0]:
//		raise SyncError(SyncError.ILLEGAL_KEY)
//	return account_no, key

string SyncableStorage::pack_key(const string &account_no, const string &enckey)
{
	if(account_no.length() != 8) {
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Account no has the wrong length");
	}
	if(enckey.length() != 32) {
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Enckey has the wrong length");
	}

	uint8_t data[42 + 1];

	memcpy(data + 0, account_no.c_str(), 8);

	memcpy(data + 8, enckey.c_str(), 32);

	uint16_t checksum = crc16(data, 32 + 8);

	uint16_t checksum_be = htons(checksum);

	memcpy(data + 40, &checksum_be, 2);

	data[43] = '\0'; // not really necessary

	char data_out[14*6 + 13 + 1];

	int i;
	for(i=0;i<14;i++) {
		sprintf(data_out + 7*i, "%02X%02X%02X", data[3*i+0], data[3*i+1], data[3*i+2]);
		if(i!=13) {
			data_out[7*i+6]='-';
		} // else sprintf already added the 0
	}

	return string(data_out);
}



//def all_keys(self, key):
//		aes_data_key=HMAC.new(key, "aes_data_key", SHA256).digest()
//		hmac_key=HMAC.new(key, "mac_key", SHA256).digest()
//		auth_token=HMAC.new(key, "auth_token", SHA256).digest()
//		return aes_data_key, hmac_key, auth_token

string SyncableStorage::GetBToken(string key)
{

}
/*	def get_btoken(self, key):
		aes_data_key, hmac_key, _=self.all_keys(key)
		iv = Random.new().read(AES.block_size)
		
		cleartext=self.encrypt_data_without_config()
		
		ciphertext = AES.new(aes_data_key, AES.MODE_CBC, iv).encrypt(cleartext)
		hmac = HMAC.new(hmac_key, ciphertext, SHA256).digest()
		
		# IV is 16 bytes, hmac is 32 bytes, ciphertext is rest
		return iv+hmac+ciphertext
*/

void SyncableStorage::PutBToken(string btoken, string key)
{

}


/*	def put_btoken(self, btoken, key):
		if len(btoken)<(4096+128+32+16): # 16 byte IV, 32 byte HMAC, 128 byte scrypt header, data in multiple of 4096
			raise SyncError(SyncError.ILLEGAL_BTOKEN)
		
		aes_data_key, hmac_key, _=self.all_keys(key)
		
		iv, hmac_received, ciphertext=btoken[0:16], btoken[16:48], btoken[48:]
		
		hmac_calculated = HMAC.new(hmac_key, ciphertext, SHA256).digest()
		if hmac_received!=hmac_calculated:
			raise SyncError(SyncError.ILLEGAL_BTOKEN)
		
		cleartext=AES.new(aes_data_key, AES.MODE_CBC, iv).decrypt(ciphertext)
		return self.decrypt_and_merge_data_without_config(cleartext)
*/	

bool SyncableStorage::SyncIsAssociated()
{
	return (config.count("sync_host") > 0) && (config.count("sync_key") > 0);
}

/*	def sync_associated(self):
		return "sync_host" in self.config
*/

/*	def read_exactly(self, sock, nbytes):
		ret=""
		while len(ret)!=nbytes:
			new=sock.read(nbytes-len(ret))
			if len(new)==0: # eof
				raise SyncError(SyncError.UNEXPECTED_COMMUNICATION_END)
			else:
				ret+=new
		return ret */
	
/*	def connect_to_sync_server(self, hostname=None, own_ca_data=None):
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
		return sock, server_protocol_version, banner */
		
string SyncableStorage::SyncSetup(string hostname, string key)
{
	if(SyncIsAssociated()) {
		throw Storage::Exception(Storage::Exception::SYNC_ALREADY_ASSOCIATED);	
	}

	config["sync_host"] = hostname;
	config["sync_key"] = key;

	changed = true;

	return "Setup ok, server not contacted yet.";
}

string SyncableStorage::SyncSetupNewAccount(string hostname)
{
	if(SyncIsAssociated()) {
		throw Storage::Exception(Storage::Exception::SYNC_ALREADY_ASSOCIATED);	
	}
	return "Not implemented yet.";
}

string SyncableStorage::SyncDeleteFromServer()
{
	if(!SyncIsAssociated()) {
		throw Storage::Exception(Storage::Exception::SYNC_NOT_ASSOCIATED);	
	}
	return "Not implemented yet.";
}

string SyncableStorage::SyncReset()
{
	if(!SyncIsAssociated()) {
		throw Storage::Exception(Storage::Exception::SYNC_NOT_ASSOCIATED);	
	}

	if(config.count("sync_key")) {
		config.erase("sync_key");	
	}
	if(config.count("sync_host")) {
		config.erase("sync_host");	
	}
	if(config.count("own_ca_data")) {
		config.erase("own_ca_data");	
	}

	changed = true;
	
	return "Not implemented yet.";
}

string SyncableStorage::Sync()
{
	if(!SyncIsAssociated()) {
		throw Storage::Exception(Storage::Exception::SYNC_NOT_ASSOCIATED);	
	}
	return "Not implemented yet.";
}
		
	/*def sync_setup(self, hostname, key, own_ca_filename=None):
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
			return self.sync_setup_new_account(hostname, key, own_ca_data) */
	
	/*def sync_setup_new_account(self, hostname, key, own_ca_data):
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
		return msg*/
	
	/*
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
	*/

/*	def sync(self):
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
*/

/*	
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
*/


string SyncableStorage::SyncGetKey() {

}

/*	
	def sync_showkey(self):
		if not self.sync_associated():
			raise SyncError(SyncError.NOT_ASSOCIATED)
		
		return self.config["sync_key"]
*/