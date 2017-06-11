#include "Record.hpp"

#include <iostream>

using namespace std;

void Record::UpdateByVect(std::string vect_name, long long vect_timestamp, std::vector<std::string> vect_value) {
	bool doUpdate;

	// TODO: Assert that vect_value has at least size 1.

	if(values.count(vect_name)) {
		pair<long long, vector<string>> prev = values[vect_name];

		long long prev_timestamp = prev.first;

		if(prev_timestamp > vect_timestamp) {
			cout << "exists, no update\n";
			doUpdate = false;
		} else {
			cout << "exists, update\n";
			doUpdate = true;
		}
	} else {
		cout << "does not exist, update\n";
		doUpdate = true;
	}

	if(doUpdate) {
		values[vect_name] = std::pair<long long, vector<string>>(vect_timestamp, vect_value);
	}
}

std::map<std::string, std::vector<std::string>> Record::GetFields() {

	map<string, vector<string>> ret;

	for(map<string, pair<long long, vector<string>>>::value_type &rec_triple : values) {
		const string &field_name = rec_triple.first;
		pair<long long, vector<string>> &field_pair = rec_triple.second;
		//long long field_timestamp = field_pair.first;
		vector<string> &field_value = field_pair.second;

		
		if(field_name.size() < 1 || field_name[0]!='_') {
			// We have found the PATH field, which gets separate treatment: you read it with GetPath().
			continue;
		}


		string field_name_shortened = field_name.substr(1, field_name.size()-1);


		if (ret.count(field_name_shortened)) {
			throw runtime_error("Unexpected duplicate path encountered in Record::GetFields.\n");
		}

		ret[field_name_shortened] = field_value;
	}

	return ret;
}

void Record::PrintRecord() {
	cout << "\t" << "rid=" << GetId() << "\n";

	for(map<string, vector<string>>::value_type &field : GetFields()) {
		cout << "\t" << field.first << "=(";
		bool first=true;
		for(const string &value : field.second) {
			if(!first) {
				cout << ", ";
			}
			cout << "'" << value << "'"; 

			first=false;
		}
		cout << ")\n";
	}
}


Record::Record(std::string record_id) {
	this->record_id = record_id;
}

std::string Record::GetPath() {
	if(values.count("PATH")) {
		return values["PATH"].second[0];
	} else {
		return "???RID="+GetId();
	}
}

std::string Record::GetId() {
	return record_id;
}