
#include "Storage.hpp"

#include <ctime>
#include <cstdio>

using json = nlohmann::json;
using namespace std;

Storage::Storage(string filename, bool create) {
	changed = false;
	
	InitCryptoStuff();
	//GenerateNewRID();

	this->filename = filename;

	json j;

	ifstream f(filename);
	
	try {
		if (f.is_open()) {
			f >> j;
			data = j[0];
			config = j[1];;
		}
	}
	catch( const exception & ex ) {
		// TODO
		cerr << ex.what() << endl;
	}
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

   	cout << "init crypt stuff done" << endl;

	
}

/*
	def __init__(self, filename, passphrase=None, create=False):
		self.filename=filename
		self.passphrase=passphrase
		self.raw=False if self.passphrase else True
		
		flags=os.O_RDWR
		if create:
			flags|=os.O_EXCL|os.O_CREAT
		fd=os.open(filename, flags, 0600)
		try:
			fcntl.lockf(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
		except IOError, e:
			if e.errno in (errno.EACCES, errno.EAGAIN):
				raise BackendError(BackendError.MULTIPLE_INSTANCES_RUNNING)
			else:
				raise
		self.f=os.fdopen(fd, "r+")
		
		if create:
			self.changed=True
			self.data={}
			self.config={}
			self.save()
		else:
			if self.raw:
				json_in=json.load(f)
				
			else:
				ciphertext=self.f.read()
				cleartext=scrypt.decrypt(ciphertext, passphrase)
				json_in=json.loads(cleartext)
			self.f.seek(0)
			
			# Backwards compatibility to the old passmate format
			if isinstance(json_in, dict):
				self.data=json_in
				self.config={}
			else:
				self.data, self.config=json_in	
			self.changed=False
*/


// This is a real cheating function, but as long as it works well, it will probably stay here.
map<string, Record> Storage::GetAllRecords() {
	map<string, Record> all_records;

	json::iterator record_it, field_it, vect_it;

	for(record_it = data.begin(); record_it != data.end(); record_it++) {
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
			throw runtime_error("Storage loaded with invalid JSON: Duplicate PATH detected.");
		} else {	
			all_records[new_record.GetPath()] = new_record;
		}

	}

	return all_records;
}


void Storage::PrintAllRecords() {
	map<string, Record> all_records = GetAllRecords();

	for(map<string, Record>::value_type &rec_pair : all_records) {
		Record &rec = rec_pair.second;
		const string &path = rec_pair.first;

		cout << path << "\n";

		rec.PrintRecord();

		cout << "\n";
	}
}

Record Storage::GetRecord(string const &path) {
	map<string, Record> all_records = GetAllRecords();

	if(all_records.count(path)) {
		return all_records[path];
	} else {
		throw runtime_error("GetRecord called on nonexistent PATH.");
	}
}

/*

	def get_all_records(self):
		records={}
		for rid, rec in self.data.items():
			path=None
			filtered_rec={"rid":rid}
			for kv in rec:
				key=kv[key_field]
				#t=kv[time_field]
				values=kv[2:]
				if key=="PATH":
					if len(values)==1:
						path=values[0]
					else:
						path=None # ignore deleted records
				if key.startswith("_"):
					filtered_rec[key]=values
			if path:
				records[path]=filtered_rec
		return records
*/

void Storage::SetPassphrase(string new_passphrase) {

}
/*
	def set_passphrase(self, new_passphrase):
		self.passphrase=new_passphrase
		self.changed=True
*/


void Storage::Close() {

}

/*
	def close(self):
		self.f.close()
*/


void Storage::Save() {
	if(!changed)
		return;

	cout << "saving!" << endl;

	string tmp_filename = filename + ".prev";
	rename(filename.c_str(), tmp_filename.c_str());

	ofstream f(filename);
	
	try {
		if (f.is_open()) {
			f << json({ data, config });
		}
	}
	catch( const exception & ex ) {
		// TODO
		cerr << ex.what() << endl;
	}
			//cout << j.dump(4) << endl;


}
/*
	def save(self):
		if not self.changed: return
		
		self.f.seek(0)
		self.f.truncate(0)
		
		if self.raw:
			json.dump([self.data, self.config], self.f)
		else:
			cleartext=json.dumps([self.data, self.config])
			cleartext=spacepad4k(cleartext)
			ciphertext=scrypt.encrypt(cleartext, self.passphrase,
				maxtime=2.5, maxmem=0, maxmemfrac=0.5)
			self.f.write(ciphertext)

		self.f.flush()
		self.f.seek(0)
*/

/*
	def encrypt_data_without_config(self):
		cleartext=json.dumps(self.data)
		cleartext=spacepad4k(cleartext)
		ciphertext=scrypt.encrypt(cleartext, self.passphrase,
			maxtime=2.5, maxmem=0, maxmemfrac=0.5)
		return ciphertext
*/

/*	
	def path_of_record(self, record):
		path=None
		for kv in record:
			key=kv[key_field]
			values=kv[2:]
			if key=="PATH":
				if len(values)==1:
					path=values[0]
				else:
					path=None
		return path
*/
/*
json Storage::MergeRecords(const json &local, const json &remote, const string &rid) {

}
*/
/*
	def merge_records(self, local, remote, rid):
		local_s=set(map(tuple, local))
		remote_s=set(map(tuple, remote))
		new_s= remote_s | local_s
		new=sorted(map(list, list(new_s)), key=lambda x: x[time_field])
		
		if contains_duplicates(map(lambda kv: (kv[key_field], kv[time_field]), new)):
			raise BackendError(BackendError.MERGE_ERROR_DUPLICATE_TIME)
			
		pushed=map(lambda kv: kv[key_field], local_s-remote_s)
		pulled=map(lambda kv: kv[key_field], remote_s-local_s)
		
		return new, MergeReportItem(rid=rid, push=pushed, pull=pulled, path=self.path_of_record(new))
*/

/*	
	def merge(self, merge_input):
		merge_report=[]
		new_data={}
		local_k=set(self.data.keys())
		remote_k=set(merge_input.keys())
		for rid in local_k|remote_k:
			if not (rid in local_k):
				local_rec=[]
			else:
				local_rec=self.data[rid]
				
			if not (rid in remote_k):
				remote_rec=[]
			else:
				remote_rec=merge_input[rid]
				
			assert len(local_rec)>0 or len(remote_rec)>0
			
			new_record, mri=self.merge_records(local_rec, remote_rec, rid)
			if mri.contains_change():
				merge_report.append(mri)
			if self.path_of_record(new_record) and self.path_of_record(new_record) in map(self.path_of_record, new_data.values()):
				raise BackendError(BackendError.MERGE_ERROR_DUPLICATE_PATH)
				
			new_data[rid]=new_record
			
		self.data=new_data
		return merge_report
*/

/*
	def decrypt_and_merge_data_without_config(self, ciphertext):
		cleartext=scrypt.decrypt(ciphertext, self.passphrase)
		json_in=json.loads(cleartext)
		return self.merge(json_in)
*/


/**************************************************************************
 * Here comes the real core stuff
 **************************************************************************/

void Storage::NewRecord(string const &path) {
	if(PathExists(path)) {
		throw Exception(Exception::PATH_ALREADY_EXISTS);
	}
	data[GenerateNewRID()]={ {"PATH", time(NULL), path} };

	changed = true;

}

string Storage::GenerateNewRID() {
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

bool Storage::PathExists(string const &path) {
	map<string, Record> all_records =  GetAllRecords();

	return all_records.count(path);
}

vector<string> Storage::List() {
	map<string, Record> all_records =  GetAllRecords();

	vector<string> ret;

	for(map<string, Record>::value_type &v : all_records) {

		ret.push_back(v.first);
	}

	return ret;

}

void Storage::DeleteRecord(string &path) {

}

/*
	def delete_record(self, path):
		self._record_set_without_underscore(path, "PATH", [])
*/

void Storage::MoveRecord(string const &new_path, string const &old_path) {

}

/*		
	def move_record(self, new_path, old_path):
		if self.path_exists(new_path):
			raise BackendError(BackendError.PATH_ALREADY_EXISTS)
		self._record_set_without_underscore(old_path, "PATH", [new_path])
*/

/*
	def fix_times(self):
		raise BackendError(BackendError.NOT_IMPLEMENTED) # TODO
*/

void Storage::RecordSetRaw(string const &path, string const &key, vector<string> const &values) {

}

/*
	def _record_set_without_underscore(self, path, key, vals):
		rid=self.get_all_records()[path]["rid"]
		now=int(time.time())
		if max(map(lambda x: x[time_field], self.data[rid])) >= now:
			raise BackendError(BackendError.NEWER_VALUE_ALREADY_EXISTS) 
		self.data[rid].append(
			[key, now]+vals
		)
		self.changed=True
*/

void Storage::RecordSet(string const &path, string const &key, vector<string> const &values) {

}

/*
	def record_set(self, path, key, vals):
		self._record_set_without_underscore(path, "_%s"%key, vals)
*/

void Storage::RecordUnset(string const &path, string const &key) {

}

/*	
	def record_unset(self, path, key):
		self.record_set(path, key, [])
*/



Storage::Exception::Exception(Storage::Exception::Err errCode) throw()
{
	this->errCode = errCode;
}

Storage::Exception::Err Storage::Exception::getErrCode()
{
	return errCode;
}

const char* Storage::Exception::what() const throw()
{
	switch(errCode) {
		case CRYPTO_ERROR: return "Error with crypto functions.";
		case FILE_ALREADY_EXISTS: return "File already exists.";
		case NOT_IMPLEMENTED: return "Not implemented.";
		case PATH_ALREADY_EXISTS: return "Path already exists.";
		case NEWER_VALUE_ALREADY_EXISTS: return "Newer value already exists.";
		case MERGE_ERROR_DUPLICATE_PATH: return "Merge error: Duplicate path.";
		case MERGE_ERROR_DUPLICATE_TIME: return "Merge error: Duplicate time.";
		case MULTIPLE_INSTANCES_RUNNING: return "Mulitple instances running.";
		
		default: return "???";
	}
}
	