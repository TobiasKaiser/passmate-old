#!/usr/bin/python
import cmd
from sync import SyncableStorage
import getpass
import sys
import os
import os.path
import string
import traceback


class PassmateCLI(cmd.Cmd):
	def __init__(self, storage):
		cmd.Cmd.__init__(self, "Tab")
		self.storage=storage
		self.path=""
		self.setprompt()
		
	def setprompt(self):
		self.prompt="%s> "%self.path
	
	def path_compfunc(self, text, line, begidx, endidx):
		# http://stackoverflow.com/questions/4001708/change-how-python-cmd-module-handles-autocompletion
		mline = line.partition(' ')[2]
		offs = len(mline) - len(text)
		complist=[s[offs:] for s in self.storage.list() if s.startswith(mline)]
		complist=map(lambda x: string.join(x.partition("/")[:2], ""), complist)
		return list(set(complist))# eliminate duplicates
	
	def field_compfunc(self, text, line, begidx, endidx):
		return []
	
	complete_move=complete_new=complete_show=complete_list=complete_open=path_compfunc
	complete_set=complete_unset=field_compfunc
	
	def do_sync_setup(self, line):
		"""Use this command to set up synchronization with a PassMate server.
		This command will ask you if you want to create a new account or connect to an existing account
		by providing the synchronization key.
		This command takes no arguments."""
		hostname=raw_input("Input server to sync with [default=passmate.net]: ")
		if hostname=="":
			hostname="passmate.net"
		key=raw_input("Enter key or press enter to create new account: ")
		if key=="":
			key=None
		custom_ca_file=raw_input("Input custom CA file or press enter for system CA: ")
		if custom_ca_file=="":
			custom_ca_file=None
		try:
			msg=self.storage.sync_setup(hostname, key, custom_ca_file)
			print msg
			self.storage.save()
		except Exception as e:
			print "Error trying to setup synchronization:"
			traceback.print_exc()
	
	def do_sync(self, line):
		"""Synchronize with PassMate server. Command takes no arguments."""
		try:
			msg=self.storage.sync()
			print msg
			self.storage.save()
		except Exception as e:
			print "Error trying to synchronize:"
			traceback.print_exc()
	
	
	def do_sync_reset(self, line):
		"""Disable synchronization. Takes no arguments.""" 
		delete_from_server=raw_input("Delete data from server (yes/no): ")
		if not (delete_from_server in "yes", "no"):
			print "Please enter 'yes' or 'no'. Reset was not successful."
			return
		try:
			msg=self.storage.sync_reset(delete_from_server=="yes")
			print msg
			self.storage.save()
		except Exception as e:
			print "Error trying to synchronize:"
			traceback.print_exc()
	
	def do_sync_showkey(self, line):
		"""Show the synchronization key."""
		passphrase_check=getpass.getpass("Enter passphrase: ")
		if self.storage.check_passphrase(passphrase_check):
			print self.storage.sync_showkey()
		else:
			print "Wrong passphrase"
	
	def do_show(self, line):
		"""Show record, takes path of the record as argument."""
		if line!="":
			if line in self.storage.list():
				self.path=line
				self.setprompt()
			else:
				print "%s not found."%line
				return
		if self.path=="": 
			print "Please specify path."
			return		
		rec=self.storage.get_all_records()[self.path]
		keys=map(lambda x: x[1:], filter(lambda x: x.startswith("_"), rec.keys()))
		if len(keys)>0:
			maxkeylen=max(map(len, keys))
			for k in keys:
				nlsplitvals=[]
				for x in rec["_%s"%k]:
					nlsplitvals+=x.split("\n")
				for i, val in enumerate(nlsplitvals):
					if i==0:
						print "%s:%s %s"%(k, " "*(maxkeylen-len(k)), val)
					else:
						print "%s  %s"%(" "*maxkeylen, val)
		else:
			print "Empty."

	def do_open(self, path):
		"""Open record, takes path of the record as agument."""
		if path=="":
			self.path=path
			self.setprompt()
		elif path in self.storage.list():
			self.path=path
			self.setprompt()
		else:
			print "%s not found."%path
	
	def do_set(self, field):
		"""Set field of record to new value. Takes name/key of the field as argument."""
		if self.path=="": 
			print "Please open path first."
			return
		
		valcount=input("How many values? ")
		vals=[]
		for i in range(valcount):
			vals+=[raw_input("%s[%i]: "%(field, i))]
		self.storage.record_set(self.path, field, vals)
		self.storage.save()
		
	def do_unset(self, field):
		"""Remove field from record. Takes name/key of the field as argument."""
		if self.path=="": 
			print "Please open path first."
			return
		self.storage.record_unset(self.path, field)
		self.storage.save()
		
	def do_delete(self, line):
		"""Delete currently opened record. No argument."""
		if self.path=="": 
			print "Please open path first."
			return
		if line!="":
			print "Delete does not take an argument. No deletion was performed."
			return
		self.storage.delete_record(self.path)
		self.storage.save()
		self.path=""
		self.setprompt()
		
	def do_move(self, new_path):
		"""Move currently opened record to new path. Takes new path as argument."""
		if self.path=="": 
			print "Please open path first."
			return
		if new_path in self.storage.list():
			print "Error: Path already exists."
			return
		self.storage.move_record(new_path, self.path)
		self.storage.save()
		self.path=new_path
		self.setprompt()
		
	def do_new(self, path):
		"""Create a new record. Takes path of enw record as argument."""
		if path in self.storage.list():
			print "Error: Path already exists."
			return
		
		self.storage.new_record(path)
		self.path=path
		self.setprompt()
		self.storage.save()
	
	def do_passwd(self, list):
		"""Change storage passphrase."""
		passphrase=getpass.getpass("Enter new passphrase: ")
		passphrase2=getpass.getpass("Repeat new passphrase: ")
		if passphrase!=passphrase2:
			print "Passphrases did not match. UPDATE WAS NOT SUCCESSFUL."
			return
		self.storage.set_passphrase(passphrase)
		self.storage.save()
	
	
	def do_EOF(self, line):
		print
		print "Please exit with 'exit'."

	def do_list(self, line):
		"""List the paths of all records."""
		for item in self.storage.list():	
			if item.startswith(line):
				print item
			
	def do_exit(self, line):
		"""Quit the program."""
		return True

def main():
	if len(sys.argv)==2:
		storage_file=sys.argv[1]
	elif len(sys.argv)<2:
		# Default storage filename
		storage_file=os.path.join(os.environ["HOME"], ".pmate")
	else:
		print "Usage: ./pmate.py [STORAGE_FILE]"
		os.exit(1)
	
	if os.path.exists(storage_file):
		passphrase=getpass.getpass("Enter passphrase to unlock password storage: ")
		storage=SyncableStorage(storage_file, passphrase)
	else:
		print "Password storage did not exist yet, will create a new one."
		passphrase=getpass.getpass("Enter new passphrase: ")
		passphrase2=getpass.getpass("Repeat new passphrase: ")
		if passphrase!=passphrase2:
			print "Passphrases did not match."
			sys.exit(1)
		storage=SyncableStorage(storage_file, passphrase, create=True)
	
	go_on=True
	
	while go_on:
		try:
			PassmateCLI(storage).cmdloop()
			go_on=False
		except KeyboardInterrupt:
			print
			print "Please exit with 'exit'."

	storage.close()

if __name__=="__main__":
	main()
