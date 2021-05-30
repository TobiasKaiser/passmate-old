import scrypt
import json
import copy
import shutil
import fcntl
import os
import os.path

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
        


class Database:
    def __init__(self, container):
        self.container=container