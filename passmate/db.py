import scrypt
import json
import copy

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
        if passphrase:
            self.is_scrypt_container = True
            self.passphrase = passphrase
        else:
            self.is_scrypt_container = False

        self.data = copy.deepcopy(self.data_template)
        self.save(create=True)


    def open(self):
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


    def save(self, create=False):
        data_plain = self.pad_string(json.dumps(self.data))

        if self.is_scrypt_container:
            assert not self.requires_passphrase

            data_scrypt = scrypt.encrypt(data_plain, self.passphrase,
                maxtime=self.maxtime, maxmem=self.maxmem, maxmemfrac=self.maxmemfrac)

            with open(self.fn, "xb" if create else "wb") as f:
                f.write(data_scrypt)
        else:
            with open(self.fn, "x" if create else "w") as f:
                f.write(data_plain)

class Database:
    pass