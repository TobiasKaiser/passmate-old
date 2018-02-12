
#include "Storage.hpp"

#include <ctime>
#include <cstdio>
#include <string>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "ScryptEnc.hpp"


using json = nlohmann::json;
using namespace std;

Storage::Storage(string filename) {
	changed = false;
	valid = false;
	paranoidFileBackup = true;
	InitCryptoStuff();
	this->filename = filename;
}


bool Storage::FileExists() {
	std::ifstream ifile(filename);
	return (bool)ifile;
}


void Storage::AcquireLock()
{
	string lock_filename = filename + ".lock";

	lockfile_fd = open(lock_filename.c_str(), O_RDWR|O_CREAT, 0666);

	if(lockfile_fd < 0) {
		throw Storage::Exception(Exception::ERROR_SAVING_FILE, "Error opening lock file");
	}

	struct flock fl;
	memset(&fl, 0, sizeof(fl));

	fl.l_type = F_WRLCK;

	// lock entire file
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;         
	fl.l_len = 0;   

	// non-blocking
	if (fcntl(lockfile_fd, F_SETLK, &fl) == -1) {
	    throw Storage::Exception(Storage::Exception::MULTIPLE_INSTANCES_RUNNING);
	}
}

void Storage::ReleaseLock()
{
	string lock_filename = filename + ".lock";

	// Do not close before unlink, else someone else might acquire a lock on a file that is deleted immediately afterwards.

	unlink(lock_filename.c_str());

	close(lockfile_fd);

}

Storage::~Storage()
{
	ReleaseLock();
}

void Storage::Open(bool create, const string &passphrase) {
	json j;

	AcquireLock();

	ifstream f(filename);
	
	if(f.good()) {
		if(create) {
			throw Exception(Exception::FILE_ALREADY_EXISTS);
		} else {
			// this case  happens in the bottom
		}
	} else {
		if(create) {
			data = json::object();
			config = json::object();
            
			valid = true;

            this->passphrase = passphrase;

            changed = true;

			return;	
		} else {
			throw Exception(Exception::FILE_NOT_FOUND);
		}
	}

	// f is good and create==false

	bool UnencryptedRequested = (passphrase.length() == 0); 

	// Check whether beginning of file is "scrypt"
	char file_id[7];
	memset(file_id, 0x00, 7);
	f.read (file_id, 6);
	bool FileHasScryptHeader = (f.gcount() == 6 && memcmp(file_id, "scrypt", 6)==0);

	// rewind
	f.clear();
	f.seekg(0);

	if(FileHasScryptHeader) {
		// encrypted file
		if(UnencryptedRequested) {
			throw Exception(Exception::WRONG_PASSPHRASE);
		}

		
		stringstream rbuf_stream;
		rbuf_stream << f.rdbuf();
		string rbuf = rbuf_stream.str();

		ScryptDecCtx dec(true);

		if(rbuf.length()-128 < 0) {
			throw Exception(Exception::CRYPTO_ERROR);	
		}

		vector<char> outbuf(rbuf.length()-128);
		
		// This throws an Storage::Exception in many cases.		
		dec.decrypt((const uint8_t *) rbuf.c_str(), rbuf.length(), (uint8_t *) &outbuf[0], NULL, (const uint8_t *) passphrase.c_str(), passphrase.length(), 16*1024*1024, 0.5, 6);

		string rbuf_cleartext(outbuf.begin(),outbuf.end());

		j = json::parse(rbuf_cleartext);
		
		data = j[0];
		config = j[1];

	} else {
		// unencrypted file
		if(!UnencryptedRequested) {
			throw Exception(Exception::WRONG_PASSPHRASE);
		}

		try {
			if (f.is_open()) {
				f >> j;
				data = j[0];
				config = j[1];;
			}
		}
		catch( const exception & ex ) {
			throw Exception(Exception::JSON_PARSE_ERROR);
		}

	}

	this->passphrase = passphrase;

	valid=true;
	
}

void Storage::InitCryptoStuff() {
	mbedtls_entropy_init(&my_entropy_ctx);

	
    mbedtls_ctr_drbg_init( &my_prng_ctx );

    int ret = mbedtls_ctr_drbg_seed(&my_prng_ctx , mbedtls_entropy_func, &my_entropy_ctx, NULL, 0);
    if( ret != 0 )
    {
        // TODO: Error handling here
   		cout << "error" << endl;
    }

   	//cout << "init crypt stuff done" << endl;

	
}


// This is a real cheating function, but as long as it works well, it will probably stay here.
map<string, Record> Storage::GetAllRecords(json *data_src)
{
	map<string, Record> all_records;

	json::iterator record_it, field_it, vect_it;

	if(!data_src) {
		data_src = &data;
	}

	for(record_it = (*data_src).begin(); record_it != (*data_src).end(); record_it++) {
		string record_id = record_it.key();
		json field_array = record_it.value();


		Record new_record(record_id);
		for(field_it=field_array.begin(); field_it != field_array.end(); field_it++) {
			json vect = field_it.value();

			string vect_name = vect[0];
			long long vect_timestamp = vect[1];

			vector<string> vect_value;

			for(vect_it=vect.begin() + 2;vect_it != vect.end(); vect_it++) {
				vect_value.push_back(vect_it.value());
			}

			new_record.UpdateByVect(vect_name, vect_timestamp, vect_value);
			
		}

		if(new_record.IsHidden())
			continue;

		if(all_records.count(new_record.GetPath())) {
			throw Storage::Exception(Storage::Exception::MERGE_ERROR_DUPLICATE_PATH, "Storage loaded with invalid JSON: Duplicate PATH detected.");
		} else {	
			all_records[new_record.GetPath()] = new_record;
		}

	}

	return all_records;
}


void Storage::PrintAllRecords()
{
	map<string, Record> all_records = GetAllRecords();

	for(map<string, Record>::value_type &rec_pair : all_records) {
		Record &rec = rec_pair.second;
		const string &path = rec_pair.first;

		cout << path << "\n";

		rec.PrintRecord();

		cout << "\n";
	}
}

Record Storage::GetRecord(string const &path)
{
	map<string, Record> all_records = GetAllRecords();

	if(all_records.count(path)) {
		return all_records[path];
	} else {
		throw runtime_error("GetRecord called on nonexistent PATH.");
	}
}

void Storage::SetPassphrase(string new_passphrase) {
	passphrase = new_passphrase;
	changed = true;
}

void Storage::Close()
{
	// This is where we could free a lock or something

	valid = false;
}

void Storage::Save()
{
	if(!changed)
		return;

	cout << "saving!" << endl;

	if(paranoidFileBackup) {
		bool counterEndReached = false;
		int counter=0;
		string backupFilename;
		while(!counterEndReached) {
			struct stat myStat;
			stringstream backupFilename_stream;
			backupFilename_stream << filename << ".bak" << setw(5) << setfill('0') << counter;
	     	backupFilename = backupFilename_stream.str();
	     	if(stat(backupFilename.c_str(),&myStat)) {
	     		counterEndReached=true;
	     	} else {
	     		counter++;
	     	}
		}
		//string tmp_filename = filename + ".prev";
		rename(filename.c_str(), backupFilename.c_str());
	}

	string filenameTempNew = filename + ".new";

	ofstream f(filenameTempNew);

	if(!f.good()) {
		throw Exception(Exception::ERROR_SAVING_FILE);
	}

	bool SaveEncrypted = (passphrase != "");

	if(SaveEncrypted) {
		// Save encrypted
		string json_str = json({ data, config }).dump();

		AddSpacePadding(json_str);

		vector<char> outbuf(json_str.length()+128);

		ScryptEncCtx enc(&my_prng_ctx);

		// This will throw a Storage:Exception in case something goes wrong		
		enc.encrypt((const uint8_t *) json_str.c_str(), json_str.length(), (uint8_t *) &outbuf[0], (const uint8_t *) passphrase.c_str(), passphrase.length(), 16*1024*1024, 0.5, 3.0);

		f.write(&outbuf[0], outbuf.size());

	} else {
		// Save JSON unencrypted
		//try {
			f << json({ data, config });
		//}
		//catch( const exception & ex ) {
		//	throw Exception(Exception::ERROR_SAVING_FILE);
		//}
	}

	rename(filenameTempNew.c_str(), filename.c_str());

}

std::string Storage::GetSyncData()
{
	// Untested so far
	string json_str = data.dump();

	AddSpacePadding(json_str);

	return json_str;
}

void Storage::AddSpacePadding(string &s)
{
	const int blocksize = 4096;

	int length = s.length();

	int blocks = ((length-1)/blocksize)+1;

	if(blocks < 1) {
		blocks = 1;
	}

	int missing_spaces = blocks * blocksize - length;

	string padding(missing_spaces, ' ');

	s += padding;
}


void Storage::MergeRecords_InsertSort(json &dest_array, const json &item)
{
	string item_name = item[0];
	long long item_timestamp = item[1];

	bool inserted=false;
	auto dest_it=dest_array.begin();
	do {
		if(dest_it == dest_array.end()) {
			dest_array.insert(dest_it, item);
			inserted = true;
		} else {
			string cur_name = dest_it.value()[0];
			long long cur_timestamp = dest_it.value()[1];

			if((cur_timestamp == item_timestamp) && (cur_name == item_name)) {
				if(item == dest_it.value()) {
					// if the values are equal, it's all good
					return;
				} else {
					throw Storage::Exception(Storage::Exception::MERGE_ERROR_DUPLICATE_TIME);
				}
			}
			if(cur_timestamp > item_timestamp) {
				dest_array.insert(dest_it, item);
				inserted = true;
			}

			dest_it++; 
		}
	} while(!inserted);

}

json Storage::MergeRecords(const json &local, const json &remote, const string &rid, ostringstream &report)
{
	json out = json::array();

	for(auto iter = local.begin(); iter != local.end(); ++iter) {
		MergeRecords_InsertSort(out, *iter);
	} 

	for(auto iter = remote.begin(); iter != remote.end(); ++iter) {
		MergeRecords_InsertSort(out, *iter);	
	} 

	return out;
}

string Storage::Merge(json merge_input)
{
	ostringstream report;

	json new_data;

	// 1. Iterate over local RIDs

	for(auto record_it = data.begin(); record_it != data.end(); record_it++) {
		string record_id = record_it.key();
		json field_array = record_it.value();

		json append_me;

		if(merge_input.count(record_id)<1) {
			append_me = field_array;
		}
		else {
			append_me = MergeRecords(field_array, merge_input[record_id], record_id, report);
			merge_input.erase(record_id);
		}

		AppendWithPathConflictCheck(new_data, record_id, append_me);
	}


	// 2. Add remaining record in merge_input to result, possibly calling merge anyways.
	for(auto record_it = merge_input.begin(); record_it != merge_input.end(); record_it++) {
		string record_id = record_it.key();
		json field_array = record_it.value();

		AppendWithPathConflictCheck(new_data, record_id, field_array);
	}

	// If no exception happens until we are here, commit new data object.
	data = new_data;

	return report.str();
}

void Storage::AppendWithPathConflictCheck(json &new_data, const string &record_id, json &field_array)
{
	Record new_record;
	for(auto field_it=field_array.begin(); field_it != field_array.end(); field_it++) {
		json vect = field_it.value();

		string vect_name = vect[0];
		long long vect_timestamp = vect[1];

		vector<string> vect_value;

		for(auto vect_it=vect.begin() + 2;vect_it != vect.end(); vect_it++) {
			vect_value.push_back(vect_it.value());
		}

		new_record.UpdateByVect(vect_name, vect_timestamp, vect_value);
	}

	string path = new_record.GetPath();

	if(GetAllRecords(&new_data).count(path)>0) {
		throw Storage::Exception(Storage::Exception::MERGE_ERROR_DUPLICATE_PATH);
	}

	new_data[record_id] = field_array;
}

string Storage::PutSyncData(string sync_data)
{
	json json_in = json::parse(sync_data);
	
	return Merge(json_in);
}

/**************************************************************************
 * Here comes the real core stuff
 **************************************************************************/

void Storage::NewRecord(string const &path)
{
	if(PathExists(path)) {
		throw Exception(Exception::PATH_ALREADY_EXISTS);
	}
	data[GenerateNewRID()]={ {"PATH", time(NULL), path} };

	changed = true;

}

string Storage::GenerateNewRID()
{
	uint32_t newRid = 0;
	string newRidStr;


	do {
		int ret;
		ret = mbedtls_ctr_drbg_random(&my_prng_ctx, (unsigned char*) &newRid, sizeof(uint32_t));

		if(ret)
		{
			// TODO: Error handling
			cout << "Error handling todo" << endl;
		}

		cout << newRid << endl;

		newRidStr = to_string(newRid);

	} while(data.count(newRidStr) > 0); // this is very unlikely to loop, only if we hit a used spot in the 32 bit RID space.


	return newRidStr;
}


bool Storage::CheckPassphrase(string const &check) {
	return check==passphrase;
}

bool Storage::PathExists(string const &path)
{
	map<string, Record> all_records =  GetAllRecords();

	return all_records.count(path);
}

vector<string> Storage::List()
{
	map<string, Record> all_records =  GetAllRecords();

	vector<string> ret;

	for(map<string, Record>::value_type &v : all_records) {

		ret.push_back(v.first);
	}

	return ret;

}

void Storage::DeleteRecord(string &path)
{
	RecordSetRaw(path, "PATH", vector<string>());
}

void Storage::MoveRecord(string const &new_path, string const &old_path)
{
	if(PathExists(new_path)) {
		throw Exception(Exception::PATH_ALREADY_EXISTS); 
	}

	RecordSetRaw(old_path, "PATH", vector<string>({new_path}));
}


void Storage::RecordSetRaw(string const &path, string const &key, vector<string> const &values)
{
	string rid = GetAllRecords()[path].GetId();

	// Todo: Check if newer value already exists. If it does, raise NEWER_VALUE_ALREADY_EXISTS exception.

	// insertMe will be [key, time(NULL), values[0], values[1], ...]
	json insertMe = json::array({key, time(NULL)});
 	for(const auto &val : values) {
		insertMe.push_back(val);
 	}
	
 	data[rid].push_back(insertMe);
 	
	changed = true;
}

void Storage::RecordSet(string const &path, string const &key, vector<string> const &values)
{
	RecordSetRaw(path, "_" + key, values);
}

void Storage::RecordUnset(string const &path, string const &key)
{
	RecordSetRaw(path, "_" + key, vector<string>());
}


// Storage::Exception
// ------------------

Storage::Exception::Exception(Storage::Exception::Err errCode) throw()
{
	this->returnCustomErrMsg = false;
	this->errCode = errCode;
	this->explaination = "";

}

Storage::Exception::Exception(Storage::Exception::Err errCode, std::string explaination) throw()
{
	this->returnCustomErrMsg = false;
	this->errCode = errCode;
	this->explaination = explaination;
	std::ostringstream ss;
	ss << what() << " (" << explaination << ")";

	std::string s(ss.str());

	strncpy(errMsg, s.c_str(), ERR_MSG_LENGTH);
	errMsg[ERR_MSG_LENGTH-1]='\0';

	returnCustomErrMsg = true;

}

Storage::Exception::Err Storage::Exception::getErrCode() const throw()
{
	return errCode;
}

const char* Storage::Exception::what() const throw()
{
	if(returnCustomErrMsg) {
		return errMsg;
	}
	switch(errCode) {
		case FILE_ALREADY_EXISTS: return "File already exists.";
		case NOT_IMPLEMENTED: return "Not implemented.";
		case PATH_ALREADY_EXISTS: return "Path already exists.";
		case NEWER_VALUE_ALREADY_EXISTS: return "Newer value already exists.";
		case MERGE_ERROR_DUPLICATE_PATH: return "Merge error: Duplicate path.";
		case MERGE_ERROR_DUPLICATE_TIME: return "Merge error: Duplicate time.";
		case MULTIPLE_INSTANCES_RUNNING: return "Mulitple instances running.";
		case CRYPTO_ERROR: return "Crypto error.";
		case FILE_NOT_FOUND: return "File not found.";
		case JSON_PARSE_ERROR: return "JSON parse error.";
		case WRONG_PASSPHRASE: return "Wrong passphrase.";		
		case ERROR_SAVING_FILE: return "Error saving file.";
		case SYNC_GENERIC_ERROR: return "Generic sync error.";
		case SYNC_SERVER_ERROR: return "Sync server error.";
		case SYNC_ALREADY_ASSOCIATED: return "Already associated with sync server.";
		case SYNC_NOT_ASSOCIATED: return "Not associated with sync server.";
		case SYNC_SERVER_PROTOCOL_VERSION_MISMATCH: return "Sync server protocol version mismatch";
		case SYNC_ILLEGAL_KEY: return "Illegal sync key.";
		case SYNC_ILLEGAL_BTOKEN: return "Illegal btoken received.";
		case SYNC_UNEXPECTED_COMMUNICATION_END: return "Unexpected end of communication.";

		default: return "???";
	}
}
