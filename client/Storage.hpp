#pragma once

#define ERR_MSG_LENGTH 256


#include <fstream>
#include <string>
#include <iostream>
#include <vector>
#include <map>


#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "Record.hpp"

#include "json/json.hpp"

//namespace nlohmann {
//	class json;
//}

class Storage {
	public:


		// Constructor and file-level functions
		Storage(std::string filename);
		~Storage();

		bool FileExists(); 
		
		void Open(bool create, const std::string &passphrase);

		void Close();

		void Save();

		// Encryption features
		void SetPassphrase(std::string new_passphrase);
		bool CheckPassphrase(std::string const &check);
		
		// Read access functions
		std::vector<std::string> List();
		Record GetRecord(std::string const &path);
		bool PathExists(std::string const &path);

		// Write access functions
		void NewRecord(std::string const &path);
		void DeleteRecord(std::string &path);
		void MoveRecord(std::string const &new_path, std::string const &old_path);
		void RecordSet(std::string const &path, std::string const &key, std::vector<std::string> const &values);
		void RecordUnset(std::string const &path, std::string const &key);

		void PrintAllRecords();
	
		void InitCryptoStuff();

		class Exception: public std::exception {
			public:

				enum Err {
					FILE_ALREADY_EXISTS=1,
					NOT_IMPLEMENTED=2,
					PATH_ALREADY_EXISTS=3,
					NEWER_VALUE_ALREADY_EXISTS=4,
					MERGE_ERROR_DUPLICATE_PATH=5,
					MERGE_ERROR_DUPLICATE_TIME=6,
					MULTIPLE_INSTANCES_RUNNING=7,
					CRYPTO_ERROR=8,
					FILE_NOT_FOUND=9,
					JSON_PARSE_ERROR=10,
					WRONG_PASSPHRASE=11,
					ERROR_SAVING_FILE=12,
					SYNC_GENERIC_ERROR=100,
					SYNC_SERVER_ERROR=101,
					SYNC_ALREADY_ASSOCIATED=102,
					SYNC_NOT_ASSOCIATED=103,
					SYNC_SERVER_PROTOCOL_VERSION_MISMATCH=104,
					SYNC_ILLEGAL_KEY=105,
					SYNC_ILLEGAL_BTOKEN=106,
					SYNC_UNEXPECTED_COMMUNICATION_END=107
		
				};

				Exception(enum Err errCode) throw();

				Exception(enum Err errCode, std::string explaination) throw();

				Err getErrCode() const throw();


				const char* what() const throw();
			private:
				enum Err errCode;
				bool returnCustomErrMsg;
				char errMsg[ERR_MSG_LENGTH];
				std::string explaination;
		};

		bool IsValid() { return valid; }

	protected:
		int lockfile_fd;

		void AcquireLock();
		void ReleaseLock();

		void AddSpacePadding(std::string &s);

		void RecordSetRaw(std::string const &path, std::string const &key, std::vector<std::string> const &values);

		std::string GenerateNewRID();
		std::map<std::string, Record> GetAllRecords(nlohmann::json *data_src = NULL);

		nlohmann::json data;
		nlohmann::json config; 

		std::string passphrase;

		mbedtls_entropy_context my_entropy_ctx;
		mbedtls_ctr_drbg_context my_prng_ctx;
    
    	bool changed;

    	bool valid;

    	std::string filename;

    	bool paranoidFileBackup;

    	std::string GetSyncData();
    	std::string PutSyncData(std::string sync_data);
    	
    	std::string Merge(nlohmann::json merge_input);
		nlohmann::json MergeRecords(const nlohmann::json &local, const nlohmann::json &remote, const std::string &rid, std::ostringstream &report);
		void MergeRecords_InsertSort(nlohmann::json &dest_array, const nlohmann::json &item);
		void AppendWithPathConflictCheck(nlohmann::json &new_data, const std::string &record_id, nlohmann::json &field_array);
};