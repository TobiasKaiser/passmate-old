#include <fstream>


void Storage::Storage(std::string filename, bool create) {

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
std::map<std::string, Record> Storage::GetAllRecords() {

}

Record Storage::GetRecord(std::string const &path) {
	
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

void Storage::SetPassphrase(std::string new_passphrase) {

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
json Storage::MergeRecords(const json &local, const json &remote, const std::string &rid) {

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

void Storage::NewRecord(std::string const &path) {

}

/*		
	def new_record(self, path):
		if self.path_exists(path):
			raise BackendError(BackendError.PATH_ALREADY_EXISTS)
		self.data[self._generate_new_rid()]=[
			["PATH", int(time.time()), path]
		]
		self.changed=True
*/


std::string Storage::GenerateNewRID() {

}

/*
	def _generate_new_rid(self):
		while True:
			rid=str(random.randint(0, 2**32))
			if not rid in self.data.keys():			
				return rid
*/

bool Storage::CheckPassphrase(std::string const &check) {
	return check==passphrase;
}

/*	
	def check_passphrase(self, check):
		return check==self.passphrase
*/

bool Storage::PathExists(std::string const &path) {

}

/*	
	def path_exists(self, path):
		return path in  self.list()
*/

std::vector<Record> Storage::List() {

}

/*		
	def list(self):
		return self.get_all_records().keys()
*/

void Storage::DeleteRecord(std::string &path) {

}

/*
	def delete_record(self, path):
		self._record_set_without_underscore(path, "PATH", [])
*/

void Storage::MoveRecord(std::string const &new_path, std::string const &old_path) {

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

void Storage::RecordSetRaw(std::string const &path, std::string const &key, std::vector<std::string> const &values) {

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

void Storage::RecordSet(std::string const &path, std::string const &key, std::vector<std::string> const &values) {

}

/*
	def record_set(self, path, key, vals):
		self._record_set_without_underscore(path, "_%s"%key, vals)
*/

void Storage::RecordUnset(std::string const &path, std::string const &key) {

}

/*	
	def record_unset(self, path, key):
		self.record_set(path, key, [])
*/