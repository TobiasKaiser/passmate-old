#pragma once

#include <fstream>
#include <string>
#include <iostream>
#include <vector>
#include <map>
#include "Record.hpp"

#include "json/json.hpp"

//namespace nlohmann {
//	class json;
//}

class Storage {
	public:

		// Constructor and file-level functions
		Storage(std::string filename, bool create);
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
	
	protected:
		void RecordSetRaw(std::string const &path, std::string const &key, std::vector<std::string> const &values);
		std::string GenerateNewRID();
		std::map<std::string, Record> GetAllRecords();

		nlohmann::json data;
		nlohmann::json config; 

		std::string passphrase;
};