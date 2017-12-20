
#include <cstdio>
#include <string>
#include <utility>

#include <arpa/inet.h>


#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

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

	return "";	
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

int SyncableStorage::SSLReadExactly(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len)
{
	/*
    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &ssl, buf, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
            break;

        if( ret < 0 )
        {
            printf( "failed\n  ! mbedtls_ssl_read returned %d\n\n", ret );
            break;
        }

        if( ret == 0 )
        {
            printf( "\n\nEOF\n\n" );
            break;
        }

        len = ret;
        printf( " %d bytes read\n\n%s", len, (char *) buf );
    }
    while( 1 );*/
    return len;
}

int SyncableStorage::SSLWriteExactly(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len)
{
	int ret;

	while( ( ret = mbedtls_ssl_write( ssl, buf, len ) ) <= 0 ) {
	    if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
	    	// in these cases we should try again. there might be some non-blocking weridness going on.
	        printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
	        break;
	    }
	}
	return ret;
	// TODO: Make sure ret is always either negative or equal to len! (partial writes are possible with mbedtls_ssl_write)
}


string SyncableStorage::PerformServerAction(enum SyncableStorage::ServerAction action)
{
	std::ostringstream output;

	//const char *server_name = "passmate.net";
	const char *server_name = "localhost";
	const char *server_port = "29556";
    const char *server_cert = "/home/tobias/workspace/passmate/server/cert.pem";


	int ret;

    mbedtls_net_context server_fd;
    mbedtls_net_init( &server_fd );
    std::unique_ptr<mbedtls_net_context, void(*)(mbedtls_net_context*)> server_fd_ptr(&server_fd, &mbedtls_net_free);

    const char *pers = "CustomString"; // ??

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    std::unique_ptr<mbedtls_ctr_drbg_context, void(*)(mbedtls_ctr_drbg_context*)> ctr_drbg_ptr(&ctr_drbg, &mbedtls_ctr_drbg_free);


    mbedtls_entropy_context entropy;
    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 ) {
    	char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        std::ostringstream error_msg;
        error_msg << "mbedtls_ctr_drbg_seed failed with return code " << ret << ": " << error_buf;
    	throw Exception(Exception::SYNC_GENERIC_ERROR, error_msg.str()); 
    }
    std::unique_ptr<mbedtls_entropy_context, void(*)(mbedtls_entropy_context*)> entropy_ptr(&entropy, &mbedtls_entropy_free);

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);
    std::unique_ptr<mbedtls_ssl_context, void(*)(mbedtls_ssl_context*)> ssl_ptr(&ssl, &mbedtls_ssl_free);
    
    mbedtls_ssl_config conf;
    mbedtls_ssl_config_init( &conf );
    std::unique_ptr<mbedtls_ssl_config, void(*)(mbedtls_ssl_config*)> mbedtls_ssl_config_ptr(&conf, &mbedtls_ssl_config_free);

    mbedtls_x509_crt cacert;
	mbedtls_x509_crt_init( &cacert );
    std::unique_ptr<mbedtls_x509_crt, void(*)(mbedtls_x509_crt*)> cacert_ptr(&cacert, &mbedtls_x509_crt_free);


   	// Load CA certificate
    ret = mbedtls_x509_crt_parse_file( &cacert, server_cert);
    if( ret < 0 ) {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        std::ostringstream error_msg;
        error_msg << "mbedtls_x509_crt_parse_file failed with return code " << ret << ": " << error_buf;
    	throw Exception(Exception::SYNC_GENERIC_ERROR, error_msg.str());
    }

    // Connect
    if( ( ret = mbedtls_net_connect( &server_fd, server_name, server_port, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        std::ostringstream error_msg;
        error_msg << "mbedtls_net_connect failed with return code " << ret << ": " << error_buf;
    	throw Exception(Exception::SYNC_GENERIC_ERROR, error_msg.str());
    }

    // Setup TLS connection
    if( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
	    char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        std::ostringstream error_msg;
        error_msg << "mbedtls_ssl_config_defaults failed with return code " << ret << ": " << error_buf;
    	throw Exception(Exception::SYNC_GENERIC_ERROR, error_msg.str());
    }

    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_REQUIRED ); // MBEDTLS_SSL_VERIFY_OPTIONAL to skip server cert check
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    
    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        std::ostringstream error_msg;
        error_msg << "mbedtls_ssl_setup failed with return code " << ret << ": " << error_buf;
    	throw Exception(Exception::SYNC_GENERIC_ERROR, error_msg.str());
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, server_name ) ) != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        std::ostringstream error_msg;
        error_msg << "mbedtls_ssl_set_hostname failed with return code " << ret << ": " << error_buf;
    	throw Exception(Exception::SYNC_GENERIC_ERROR, error_msg.str());
    }

    mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
	      	char error_buf[100];
	        mbedtls_strerror( ret, error_buf, 100 );
	        std::ostringstream error_msg;
	        error_msg << "mbedtls_ssl_handshake failed with return code " << ret << ": " << error_buf;
	    	throw Exception(Exception::SYNC_GENERIC_ERROR, error_msg.str());
        }
    }

    // Verify server certificate <== only necessary when MBEDTLS_SSL_VERIFY_OPTIONAL is used above
	/*uint32_t flags;
    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        printf( " failed\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        printf( "%s\n", vrfy_buf );
        // TODO: Throw error!!!!
    }*/


    SSLWriteExactly(&ssl, (unsigned char*)"Hello", 5);

    switch(action) {
	case CREATE:
		break;
	case UPDATE:
		break;
	case RESET:

		break;
    }

    mbedtls_ssl_close_notify( &ssl );

    return output.str();
}
	
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

	return PerformServerAction(UPDATE);
}

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
	return "???";
}

/*	
	def sync_showkey(self):
		if not self.sync_associated():
			raise SyncError(SyncError.NOT_ASSOCIATED)
		
		return self.config["sync_key"]
*/