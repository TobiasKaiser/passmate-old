#pragma once


#include <string>
#include <vector>
#include <map>

class Storage;

class Record {
	public:
		Record(std::string record_id);
		Record(const Record &obj) {
			record_id = obj.record_id;
			values = obj.values;
		}
		Record() { record_id = "INVALID"; } // This is somehow necessary for the map to work -,-


		// UpdateByVect is called by the Strorage class to populate the records.
		void UpdateByVect(std::string vect_name, long long vect_timestamp, std::vector<std::string> vect_value);
		
		std::string GetPath();

		std::string GetId();

		void PrintRecord();

		bool IsHidden(); // True if deleted or no PATH set. 

		// This function is for the GUI to get the data from what is in the record at the moment. Changes have to be done via the Storage class.
		std::map<std::string, std::vector<std::string>> GetFields();

		std::string SetNewFieldsToStorage(Storage &dest, std::map<std::string, std::vector<std::string>> &newFields, bool dryRun);

	protected:
		std::map<std::string, std::pair<long long,std::vector<std::string>>> values;

		std::string record_id;

};