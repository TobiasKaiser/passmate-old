import json
import os
import os.path
import time
import random
import scrypt
import copy
import collections
import string
import fcntl
import errno

time_field=1
key_field=0


class MergeReportItem(collections.namedtuple("MergeReportItem", ['rid', 'path', 'push', 'pull'])):
	def indicator(self):
		if len(self.push)>0 and len(self.pull)>0:
			return "-><-"
		elif len(self.push)>0:
			return "  <-"
		elif len(self.pull)>0:
			return "->  "
		else:
			return "    "
	def contains_change(self):
		return len(self.push)>0 or len(self.pull)>0
	
	def lineformat(self):
		msgs=[]
		for k in self.push:
			if k=="PATH":
				msgs.append("push new path")
			elif k[0]=='_':
				msgs.append("push new value for field '%s'"%k[1:])
		for k in self.pull:
			if k=="PATH":
				msgs.append("pull new path")
			elif k[0]=='_':
				msgs.append("pull new value for field '%s'"%k[1:])
		if len(msgs)>0:
			msg=(string.join(msgs, ", ")+".").capitalize()
		else:
			msg="No change."
		return "%s %s (%s): %s"%(self.indicator(), self.path, self.rid, msg)
	
def spacepad4k(text):
	if len(text)%4096==0:
		return text
	else:
		return text+(" "*(4096-(len(text)%4096)))

class BackendError(Exception):
	GENERIC=0
	FILE_ALREADY_EXISTS=1
	NOT_IMPLEMENTED=2
	PATH_ALREADY_EXISTS=3
	NEWER_VALUE_ALREADY_EXISTS=4
	MERGE_ERROR_DUPLICATE_PATH=5
	MERGE_ERROR_DUPLICATE_TIME=6
	MULTIPLE_INSTANCES_RUNNING=7
	def __init__(self, number, message=""):
		super(BackendError, self).__init__(message)
		self.number = number

def contains_duplicates(l):
	return len(l)!=len(set(l))

class Storage:
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
			
	def set_passphrase(self, new_passphrase):
		self.passphrase=new_passphrase
		self.changed=True

	def close(self):
		self.f.close()
	
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

	def encrypt_data_without_config(self):
		cleartext=json.dumps(self.data)
		cleartext=spacepad4k(cleartext)
		ciphertext=scrypt.encrypt(cleartext, self.passphrase,
			maxtime=2.5, maxmem=0, maxmemfrac=0.5)
		return ciphertext
	
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
			
	
	def decrypt_and_merge_data_without_config(self, ciphertext):
		cleartext=scrypt.decrypt(ciphertext, self.passphrase)
		json_in=json.loads(cleartext)
		return self.merge(json_in)
		
	def new_record(self, path):
		if self.path_exists(path):
			raise BackendError(BackendError.PATH_ALREADY_EXISTS)
		self.data[self._generate_new_rid()]=[
			["PATH", int(time.time()), path]
		]
		self.changed=True

	def _generate_new_rid(self):
		while True:
			rid=str(random.randint(0, 2**32))
			if not rid in self.data.keys():			
				return rid
	
	def check_passphrase(self, check):
		return check==self.passphrase
	
	def path_exists(self, path):
		return path in  self.list()
		
	def list(self):
		return self.get_all_records().keys()

	def delete_record(self, path):
		self._record_set_without_underscore(path, "PATH", [])
		
	def move_record(self, new_path, old_path):
		if self.path_exists(new_path):
			raise BackendError(BackendError.PATH_ALREADY_EXISTS)
		self._record_set_without_underscore(old_path, "PATH", [new_path])

	def fix_times(self):
		raise BackendError(BackendError.NOT_IMPLEMENTED) # TODO

	def _record_set_without_underscore(self, path, key, vals):
		rid=self.get_all_records()[path]["rid"]
		now=int(time.time())
		if max(map(lambda x: x[time_field], self.data[rid])) >= now:
			raise BackendError(BackendError.NEWER_VALUE_ALREADY_EXISTS) 
		self.data[rid].append(
			[key, now]+vals
		)
		self.changed=True

	def record_set(self, path, key, vals):
		self._record_set_without_underscore(path, "_%s"%key, vals)
	
	def record_unset(self, path, key):
		self.record_set(path, key, [])
