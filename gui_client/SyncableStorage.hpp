#pragma once


#include <fstream>
#include <string>
#include <iostream>
#include <vector>
#include <map>

#include "Storage.hpp"

class SyncableStorage : public Storage {
	public:
		SyncableStorage(std::string filename) : Storage(filename) {}

		bool SyncIsAssociated();
		std::string SyncGetKey();


		// SyncSetup, SyncSetupNewAccount, SyncDeleteFromServer, SyncReset, Sync:
		// Blocking network stuff, return summary string on success, throw exception if something goes wrong.

		// Setup: Connect to existing account
		std::string SyncSetup(std::string hostname, std::string key);

		// Setup: Create new account
		std::string SyncSetupNewAccount(std::string hostname);
		
		// Deassociate and delete all data from server
		std::string SyncDeleteFromServer();

		// Deassociate but keep all data on server
		std::string SyncReset();

		// Synchronize password storage with server
		std::string Sync();

		static void unpack_key(const std::string &key, std::string &account_no, std::string &enckey);
		static uint16_t crc16(const uint8_t *data, size_t len);
		static std::string pack_key(const std::string &account_no, const std::string &enckey);
	protected:
		std::string GetBToken(std::string key);
		void PutBToken(std::string btoken, std::string key);


		constexpr static const char *handshake1 = "passmate-server-protocol";
		constexpr static const char *handshake2 = "passmate-protocol-server";


};