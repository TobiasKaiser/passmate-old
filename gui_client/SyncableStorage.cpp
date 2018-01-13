
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

void SyncableStorage::DeriveKeys(const string &enckey, string &aes_data_key, string &hmac_key, string &auth_token)
{
	// this used to be all_keys in the python implementation

	vector<char> aes_data_key_vect(32), hmac_key_vect(32), auth_token_vect(32);

	string aes_data_key_src = "aes_data_key";
	string hmac_key_src = "mac_key";
	string auth_token_src = "auth_token";

	mbedtls_md_context_t hctx;	
	
	mbedtls_md_init(&hctx);  
	mbedtls_md_setup(&hctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&hctx, (const unsigned char *) &enckey[0], 32);
	mbedtls_md_hmac_update(&hctx, (const unsigned char *) aes_data_key_src.c_str(), aes_data_key_src.length());    
	mbedtls_md_hmac_finish(&hctx, (unsigned char *) &aes_data_key_vect[0]);
	mbedtls_md_free(&hctx);

	mbedtls_md_init(&hctx);  
	mbedtls_md_setup(&hctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&hctx, (const unsigned char *) &enckey[0], 32);
	mbedtls_md_hmac_update(&hctx, (const unsigned char *) hmac_key_src.c_str(), hmac_key_src.length());    
	mbedtls_md_hmac_finish(&hctx, (unsigned char *) &hmac_key_vect[0]);
	mbedtls_md_free(&hctx);

	mbedtls_md_init(&hctx);  
	mbedtls_md_setup(&hctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&hctx, (const unsigned char *) &enckey[0], 32);
	mbedtls_md_hmac_update(&hctx, (const unsigned char *)auth_token_src.c_str(), auth_token_src.length());    
	mbedtls_md_hmac_finish(&hctx, (unsigned char *) &auth_token_vect[0]);
	mbedtls_md_free(&hctx);

	string aes_data_key_new(aes_data_key_vect.begin(), aes_data_key_vect.end());
	string hmac_key_new(hmac_key_vect.begin(), hmac_key_vect.end());
	string auth_token_new(auth_token_vect.begin(), auth_token_vect.end());

	aes_data_key = aes_data_key_new;
	hmac_key = hmac_key_new;
	auth_token = auth_token_new;
}

string SyncableStorage::GetBToken(string key)
{
	return "test token";	
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

string SyncableStorage::PutBToken(string btoken, string key)
{
	cout << "Put btoken..." << endl;

	return "blub...";
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

int SyncableStorage::SSLReadExactly(mbedtls_ssl_context *ssl, unsigned char *buf, size_t len)
{
	int ret;
	int len_remaining = len;
	while(len_remaining > 0) {
		ret = mbedtls_ssl_read(ssl, buf, len_remaining);

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ) {
            continue;
        }
        else if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ) {
        	throw Exception(Exception::SYNC_UNEXPECTED_COMMUNICATION_END);
        }
		else if( ret == 0 ) { // End of file
            throw Exception(Exception::SYNC_UNEXPECTED_COMMUNICATION_END);
        }
        else if( ret < 0 ) {
            char error_buf[100];
	        mbedtls_strerror( ret, error_buf, 100 );
	        std::ostringstream error_msg;
	        error_msg << "mbedtls_ssl_read failed with return code " << ret << ": " << error_buf;
	    	throw Exception(Exception::SYNC_GENERIC_ERROR, error_msg.str());
        }

        len_remaining -= ret;
        buf += ret;
    }
    if(len_remaining != 0) {
    	throw Exception(Exception::SYNC_GENERIC_ERROR, "Unable to read requested amount of data.");
    }
    return len;
}

int SyncableStorage::SSLWriteExactly(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len)
{
	int ret;

	while( ( ret = mbedtls_ssl_write( ssl, buf, len ) ) <= 0 ) {
	    if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ) {
	    	// in these cases we should try again. there might be some non-blocking weridness going on.
	    }
	    else {
	    	char error_buf[100];
	        mbedtls_strerror( ret, error_buf, 100 );
	        std::ostringstream error_msg;
	        error_msg << "mbedtls_ssl_write failed with return code " << ret << ": " << error_buf;
	    	throw Exception(Exception::SYNC_GENERIC_ERROR, error_msg.str());
        
	        break;
	    }
	}
	return ret;
	// TODO: Make sure ret is always either negative or equal to len! (partial writes are possible with mbedtls_ssl_write)
}

	/*
		
			
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
	*/



void SyncableStorage::CommunicateCreate(mbedtls_ssl_context *ssl, ostringstream &output)
{
	if(SyncIsAssociated()) {
		throw Storage::Exception(Storage::Exception::SYNC_ALREADY_ASSOCIATED);	
	}

	vector<char> enckey_vect(32);
	mbedtls_ctr_drbg_random(&my_prng_ctx, (unsigned char *) &enckey_vect[0], 32);

	string enckey(enckey_vect.begin(), enckey_vect.end());

	string aes_data_key, hmac_key, auth_token;
	DeriveKeys(enckey, aes_data_key, hmac_key, auth_token);

	// Send command
	char command = 'c'; // c = update
    SSLWriteExactly(ssl, (unsigned char*) &command, 1);

	// Send auth token to server. We will then receive an account no from server.
	SSLWriteExactly(ssl, (unsigned char*) auth_token.c_str(), auth_token.length());

    // Send btoken
	string btoken_send = GetBToken(enckey);
	uint32_t len_btoken_send = htonl(btoken_send.length());
	SSLWriteExactly(ssl, (unsigned char *) &len_btoken_send, 4);
	SSLWriteExactly(ssl, (unsigned char *) btoken_send.c_str(), btoken_send.length());

	// Receive account no as confirmation
	vector<char> account_no_recv_vect(8);
	vector<char> account_no_failure_vect(8);
	memset(&account_no_failure_vect[0], 0, 8); // TODO: make this a bit more c++y

	SSLReadExactly(ssl, (unsigned char *) &account_no_recv_vect[0], 8);
	string account_no_recv(account_no_recv_vect.begin(), account_no_recv_vect.end());
	if(account_no_recv_vect == account_no_failure_vect) {
		throw Storage::Exception(Storage::Exception::SYNC_SERVER_ERROR);
	}

	config["sync_key"] = pack_key(account_no_recv, enckey);
}
	


void SyncableStorage::CommunicateUpdate(mbedtls_ssl_context *ssl, ostringstream &output)
{
	if(!SyncIsAssociated()) {
		throw Storage::Exception(Storage::Exception::SYNC_NOT_ASSOCIATED);	
	}

	string account_no, enckey;
	unpack_key(config["sync_key"], account_no, enckey);

	string aes_data_key, hmac_key, auth_token;
	DeriveKeys(enckey, aes_data_key, hmac_key, auth_token);

	// Send command
	char command = 'u'; // u = update
    SSLWriteExactly(ssl, (unsigned char*) &command, 1);

    // Send account no and auth token
	SSLWriteExactly(ssl, (unsigned char*) account_no.c_str(), account_no.length());
	SSLWriteExactly(ssl, (unsigned char*) auth_token.c_str(), auth_token.length());

	// Receive btoken
	uint32_t len_btoken_recv_n, len_btoken_recv;
	SSLReadExactly(ssl, (unsigned char *) &len_btoken_recv_n, 4);
    len_btoken_recv = ntohl(len_btoken_recv_n);
    if(len_btoken_recv > 32 * 1024 * 1024) {
    	throw Storage::Exception(Storage::Exception::SYNC_GENERIC_ERROR, "Btoken size received exceeds btoken size limit.");
    }
    vector<char> btoken_recv_vect(len_btoken_recv);
    SSLReadExactly(ssl, (unsigned char *) &btoken_recv_vect[0], len_btoken_recv);
    string btoken_recv(btoken_recv_vect.begin(), btoken_recv_vect.end());
    output << "========================================" << endl;
    output << PutBToken(btoken_recv, enckey); // TODO: Improve reporting


    // Send btoken
	string btoken_send = GetBToken(enckey);
	uint32_t len_btoken_send = htonl(btoken_send.length());
	SSLWriteExactly(ssl, (unsigned char *) &len_btoken_send, 4);
	SSLWriteExactly(ssl, (unsigned char *) btoken_send.c_str(), btoken_send.length());

	// Receive account no as confirmation
	vector<char> account_no_recv_vect(8); 	
	SSLReadExactly(ssl, (unsigned char *) &account_no_recv_vect[0], 8);
	string account_no_recv(account_no_recv_vect.begin(), account_no_recv_vect.end());
	if(account_no_recv != account_no) {
		throw Storage::Exception(Storage::Exception::SYNC_SERVER_ERROR);
	}
}

	
void SyncableStorage::CommunicateReset(mbedtls_ssl_context *ssl, ostringstream &output)
{
	if(!SyncIsAssociated()) {
		throw Storage::Exception(Storage::Exception::SYNC_NOT_ASSOCIATED);	
	}

	string account_no, enckey;
	unpack_key(config["sync_key"], account_no, enckey);

	string aes_data_key, hmac_key, auth_token;
	DeriveKeys(enckey, aes_data_key, hmac_key, auth_token);

	// Send command
	char command = 'r'; // r = reset
    SSLWriteExactly(ssl, (unsigned char*) &command, 1);

    // Send account no and auth token
	SSLWriteExactly(ssl, (unsigned char*) account_no.c_str(), account_no.length());
	SSLWriteExactly(ssl, (unsigned char*) auth_token.c_str(), auth_token.length());

	// Receive account no as confirmation
	vector<char> account_no_recv_vect(8); 	
	SSLReadExactly(ssl, (unsigned char *) &account_no_recv_vect[0], 8);
	string account_no_recv(account_no_recv_vect.begin(), account_no_recv_vect.end());
	if(account_no_recv != account_no) {
		throw Storage::Exception(Storage::Exception::SYNC_SERVER_ERROR);
	}
}

string SyncableStorage::PerformServerAction(enum SyncableStorage::ServerAction action)
{
	ostringstream output;

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


	static const char *handshake1 = "passmate-server-protocol";
	static const char *handshake2 = "passmate-protocol-server";


    SSLWriteExactly(&ssl, (unsigned char*) handshake1, 24);
    char handshake_recvd[24];
    SSLReadExactly(&ssl, (unsigned char*) handshake_recvd, 24);

    uint16_t server_protocol_version_n, server_protocol_version; // _n is for network byte order
    uint32_t banner_length_n, banner_length;

    SSLReadExactly(&ssl, (unsigned char *) &server_protocol_version_n, 2);

    server_protocol_version = ntohs(server_protocol_version_n);

    if(server_protocol_version != 2) {
    	throw Exception(Exception::SYNC_SERVER_PROTOCOL_VERSION_MISMATCH);
    }

    SSLReadExactly(&ssl, (unsigned char *) &banner_length_n, 4);

    banner_length = ntohl(banner_length_n);

    if(banner_length > 32 * 1024) {
    	throw Exception(Exception::SYNC_GENERIC_ERROR, "Banner length exceeds maximum banner length.");
    }

    vector<char> banner_vect(banner_length);

    SSLReadExactly(&ssl, (unsigned char *) &banner_vect[0], banner_length);

 	std::string banner(banner_vect.begin(),banner_vect.end());

 	output << "Banner received:" << endl << banner << endl;

    if(memcmp(handshake_recvd, handshake2,24) != 0) {
    	throw Exception(Exception::SYNC_SERVER_ERROR);
    }

    switch(action) {
		case CREATE:
			CommunicateCreate(&ssl, output);
			break;
		case UPDATE:
			CommunicateUpdate(&ssl, output);
			break;
		case RESET:
			CommunicateReset(&ssl, output);
			break;
    }

    mbedtls_ssl_close_notify( &ssl );

    return output.str();
}
		
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

	string report = PerformServerAction(CREATE);

	// we only come here on success
	config["sync_host"] = hostname;

	changed = true;

	return report;
}

string SyncableStorage::SyncDeleteFromServer()
{
	if(!SyncIsAssociated()) {
		throw Storage::Exception(Storage::Exception::SYNC_NOT_ASSOCIATED);	
	}

	return PerformServerAction(RESET);
}

string SyncableStorage::SyncReset(bool delete_from_server)
{
	string msg="";
	if(!SyncIsAssociated()) {
		throw Storage::Exception(Storage::Exception::SYNC_NOT_ASSOCIATED);	
	}

	if(delete_from_server) {
		msg = SyncDeleteFromServer();
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
	
	return msg;
}


string SyncableStorage::Sync()
{
	if(!SyncIsAssociated()) {
		throw Storage::Exception(Storage::Exception::SYNC_NOT_ASSOCIATED);	
	}

	changed = true; // not sure we need this

	return PerformServerAction(UPDATE);
}


string SyncableStorage::SyncGetKey()
{
	if(!SyncIsAssociated()) {
		throw Storage::Exception(Storage::Exception::SYNC_NOT_ASSOCIATED);	
	}
	
	return config["sync_key"];
}