import copy
import collections
import time
from pathlib import Path
import glob

import secrets
import base64

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
        return f"<DatabaseUpdate db_key={self.db_key} {self.describe()}>"
    
    def apply(self, db_recs, timestamp):
        if not self.db_key in db_recs:
            db_recs[self.db_key] = []
        db_recs[self.db_key].append(
            [self.raw_field_name, timestamp] + self.raw_field_values
        )

class Record:
    """
    fields: This dictionary should be modified through the frontend.
    db_fields: Remembers values of fields as read from container
    db_path: Remembers path as read from container
    """

    @staticmethod
    def random_key():
        return base64.b16encode(secrets.token_bytes(8)).decode("ascii")

    def __init__(self, db, db_key=None, db_tuples=None):
        self.db = db
        if db_key:
            self.db_key = db_key
        else:
            self.db_key = self.random_key()

        if db_tuples:
            self.db_fields=db_tuples.get_fields()
            self.db_path=db_tuples.get_path()
        else:
            self.db_fields={}
            self.db_path=None

        # .fields are the working copy,
        # .db_fields and .db_path remeber the db state.
        self.fields=copy.deepcopy(self.db_fields)

    def mark_as_up_to_date(self):
        self.db_fields = copy.deepcopy(self.fields)
        self.db_path = self.get_cur_path()
    
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

        for field_name in db_field_names | cur_field_names:
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
                updates.append(DatabaseUpdate(self.db_key, "_"+field_name, update_value))

        return updates

    def __repr__(self):
        keys = list(self.fields.keys())
        return f"<Record with fields {keys}>"

class Database:
    def __init__(self, container, synchronizer=None):
        self.container=container
        self.migrate_container()
        self.read_container()
        self.synchronizer = synchronizer

    def get_updates(self):
        updates = []
        for r in self.records.values():
            updates+=r.get_updates()
        return updates

    def update(self):
        t = int(time.time())
        for u in self.get_updates():
            u.apply(self.container.data["records"], t)

        for r in self.records.values():
            r.mark_as_up_to_date()

    def save(self):
        self.update()
        self.container.save()
        if self.synchronizer.push_fn:
            Path(self.synchronizer.push_fn).parent.mkdir(parents=True, exist_ok=True)
            self.container.save(filename=self.synchronizer.push_fn, working_copy=False)


    def merge(self, rc):
        # rc = remote container
        """Warning: this writes straight to self.container.data and invalidates
        all changes to self.records that were not saved prior to the merge() call."""
        for db_key, field_tuples in rc.data["records"].items():
            if db_key in self.container.data["records"]:
                # Merge
                for tup in field_tuples:
                    if not tup in self.container.data["records"][db_key]:
                        print(db_key, tup)
                        self.container.data["records"][db_key].append(tup)
            else:
                # Add new record
                self.container.data["records"][db_key] = field_tuples

        self.read_container()


    def migrate_container(self):
        if isinstance(self.container.data, list):
            # Old passmate format [records, config]
            print("Warning: Migrating to new database format.")
            records = self.container.data[0]
            self.container.data = copy.deepcopy(self.container.data_template)
            self.container.data["records"] = records

        assert self.container.data["version"] == 1

    def read_container(self):
        """Transforms the container JSON into .records, a dict of Records."""
        
        self.records={}

        for db_key, field_tuples in self.container.data["records"].items():
            tups = FieldTuples(field_tuples)
            rec = Record(self, db_key, tups)
            if not rec.db_path:
                continue
            if rec.db_path in self.records:
                raise ValueError("Duplicate record path")
            self.records[rec.db_path] = rec

class Synchronizer:
    def __init__(self, push_fn, pull_glob):
        self.push_fn = push_fn
        self.pull_glob = pull_glob

    def get_pull_filenames(self):
        for fn in glob.glob(self.pull_glob):
            if fn != self.push_fn:
                yield fn

class NoSynchronizer(Synchronizer):
    def __init__(self):
        self.push_fn = None

    def get_pull_filenames(self):
        return []
