import scrypt
import json
import copy
import shutil
import fcntl
import collections
import os
import os.path
import time

class DatabaseContainer:
    maxtime = 1.0
    maxmem = 16*1024*1024
    maxmemfrac = 0.5

    padding_increment = 4096

    data_template = {}

    @staticmethod
    def get_default_container_fn():
        from pathlib import Path

        return Path.home().joinpath(".pmate3")

    def __init__(self, fn):
        self.fn = fn

    def create(self, passphrase):
        self.acquire_lock()
        assert not os.path.exists(self.fn)

        if passphrase:
            self.is_scrypt_container = True
            self.passphrase = passphrase
        else:
            self.is_scrypt_container = False

        self.data = copy.deepcopy(self.data_template)
        self.save(create=True)


    def open(self):
        self.acquire_lock()

        with open(self.fn, "rb") as f:
            head = f.read(6)

        if head == b"scrypt":
            self.is_scrypt_container = True
            self.requires_passphrase = True
        else:
            self.is_scrypt_container = False
            self.requires_passphrase = False

            # Load plaintext json
            with open(self.fn, "r") as f:
                self.data = json.load(f)

    def decrypt(self, passphrase):
        assert self.is_scrypt_container and self.requires_passphrase
        
        with open(self.fn, "rb") as f:
            data_scrypt = f.read()
        
        data = scrypt.decrypt(data_scrypt, passphrase)
        self.data = json.loads(data)

        self.passphrase = passphrase
        self.requires_passphrase = False

    @classmethod
    def pad_string(cls, str_in):
        padded_len = (((len(str_in)-1)//cls.padding_increment)+1)*cls.padding_increment
        return str_in.ljust(padded_len)

    @property
    def fn_tmp(self):
        return f"{self.fn}.tmp"

    @property
    def fn_lock(self):
        return f"{self.fn}.lock"

    def save(self, create=False):
        """Save container. To ensure that no inconsistent database is written
        even in the event of a crash, a new container file is written and then
        moved to replace the previous container file."""
        data_plain = json.dumps(self.data)

        if self.is_scrypt_container:
            assert not self.requires_passphrase

            data_plain_padded = self.pad_string(data_plain)

            data_scrypt = scrypt.encrypt(data_plain_padded, self.passphrase,
                maxtime=self.maxtime, maxmem=self.maxmem, maxmemfrac=self.maxmemfrac)

            with open(self.fn_tmp, "wb") as f:
                f.write(data_scrypt)
        else:
            with open(self.fn_tmp, "w") as f:
                f.write(data_plain)

        shutil.move(self.fn_tmp, self.fn)

    def acquire_lock(self):
        """This method acquires a lock via a separate file. A separate file is
        used because a new container file is always created when save() is called."""
        self.lock_file = open(self.fn_lock, "w")
        fcntl.lockf(self.lock_file, fcntl.LOCK_EX|fcntl.LOCK_NB)

    def release_lock(self):
        """Releases the lock acquired through acquire_lock()."""

        #Do not close before unlink, else someone else might acquire a lock on a file that is deleted immediately afterwards.
        os.unlink(self.lock_fn)
        close(self.lock_file)

class FieldTuples:
    FieldValue = collections.namedtuple('FieldValue', ['time', 'value'])
    
    def __init__(self, field_tuples):
        #self.field_tuples = field_tuples
        self.raw_fields = self.raw_fields(field_tuples)

    @staticmethod
    def raw_fields(field_tuples):
        raw_fields={}

        for tup in field_tuples:
            field_name, field_time, field_value = tup[0], int(tup[1]), tup[2:]
            if field_name in raw_fields:
                # Only update the field if the values read are more recent than our current field value.
                update = raw_fields[field_name].time < field_time
            else:
                update = True
            if update:
                raw_fields[field_name] = FieldTuples.FieldValue(field_time, field_value)

        return raw_fields

    def get_fields(self):
        fields = {}
        for field_name, field in self.raw_fields.items():
            if field_name.startswith("_") and len(field.value)>0:
                fields[field_name[1:]]=field.value
        return fields

    def get_path(self):
        path_value = self.raw_fields["PATH"].value
        assert len(path_value) <= 1
        if len(path_value)==1:
            return path_value[0]
        else:
            return None

class DatabaseUpdate:
    def __init__(self, db_key, raw_field_name, raw_field_values):
        self.db_key = db_key
        self.raw_field_name = raw_field_name
        self.raw_field_values = raw_field_values

    def describe(self):
        if self.raw_field_name == "PATH":
            if len(self.raw_field_values) == 0:
                return f'delete record'
            elif len(self.raw_field_values) == 1:
                return f'set record name to "{self.raw_field_values[0]}"'
            else:
                assert False # Unexpected length of PATH value
        elif self.raw_field_name.startswith("_"):
            field_name = self.raw_field_name[1:]
            if len(self.raw_field_values) == 0:
                return f'delete field "{field_name}"'
            else:
                return f'set field "{field_name}" to {self.raw_field_values}'
        else:
            assert False # Unexpected raw_field_name in update

    def __repr__(self):
        return f"<DatabaseUpdate {self.describe()}>"


class Record:
    """
    fields: This dictionary should be modified through the frontend.
    db_fields: Remembers values of fields as read from container
    db_path: Remembers path as read from container
    """

    def __init__(self, db, db_key, db_tuples=None):
        self.db = db
        self.db_key = db_key

        if db_tuples:
            self.db_fields=db_tuples.get_fields()
            self.db_path=db_tuples.get_path()
        else:
            self.db_fields={}
            self.db_path=None

        # .fields are the working copy,
        # .db_fields and .db_path remeber the db state.
        self.fields=copy.deepcopy(self.db_fields)
    
    def get_cur_path(self):
        cur_path = None
        for path, rec in self.db.records.items():
            if rec == self:
                cur_path = path
        return cur_path

    def get_updates(self):
        updates = []

        # Update PATH
        cur_path = self.get_cur_path()
        if cur_path != self.db_path:
            if cur_path:
                updates.append(DatabaseUpdate(self.db_key, "PATH", [cur_path]))
            else:
                updates.append(DatabaseUpdate(self.db_key, "PATH", []))
        

        db_field_names  = set(self.db_fields.keys())
        cur_field_names = set(self.fields.keys())

        for field_name in db_field_names + cur_field_names:
            update_value = None
            if not (field_name in cur_field_names):
                # Delete field:
                update_value = []
            elif not (field_name in db_field_names):
                # New field:
                update_value = self.fields[field_name]
            elif self.fields[field_name] != self.db_fields[field_name]:
                # Value changed:
                update_value = self.fields[field_name]

            if update_value != None:
                updates.append(DatabaseUpdate(self.db_key, "_"+field_name), update_value)

        return updates


    def __repr__(self):
        keys = list(self.fields.keys())
        return f"<Record with fields {keys}>"

class Database:
    def __init__(self, container):
        self.container=container
        self.read_container()

    def read_container(self):
        """Transforms the container JSON into .records, a dict of Records."""
        
        self.records={}

        for db_key, field_tuples in self.container.data[0].items():
            tups = FieldTuples(field_tuples)
            rec = Record(self, db_key, tups)
            if not rec.db_path:
                continue
            if rec.db_path in self.records:
                raise ValueError("Duplicate record path")
            self.records[rec.db_path] = rec
            print(rec.db_path, rec)
