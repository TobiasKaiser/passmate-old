from .db import *
import getpass
import argparse
import cmd

class CLI(cmd.Cmd):

    def __init__(self, db):
        super().__init__()
        self.cur_record = None
        self.db = db

    @property
    def prompt(self):
        if self.cur_record:
            return f"pmate:{self.cur_record}>"
        else:
            return "pmate> "
    

    def do_get_json(self, arg):
        """Print container JSON"""
        print(self.db.container.data)

    def do_save(self, arg):
        """Save container"""
        self.db.container.save()

    def do_quit(self, arg):
        """Exit passmate CLI"""
        return True

    def do_EOF(self, arg):
        return True

def cli_get_db():
    ap = argparse.ArgumentParser()
    ap.add_argument("container", nargs="?", help="Password database container file")
    ap.add_argument("-c", "--create", action="store_true", help="Create new password container file")
    args = ap.parse_args()

    if args.container:
        container_fn = args.container
    else:
        container_fn = DatabaseContainer.get_default_container_fn()

    container = DatabaseContainer(container_fn)

    if args.create:
        passphrase1 = getpass.getpass(f'Passphrase to create {container_fn}: ')
        passphrase2 = getpass.getpass(f'Repeat passphrase to create {container_fn}: ')
        if passphrase1 != passphrase2:
            raise ValueError("Passphrases did not match.")

        container.create(passphrase1)

    else:
        container.open()
        while container.requires_passphrase:
            passphrase = getpass.getpass(f'Passphrase to open {container_fn}: ')
            container.decrypt(passphrase)

    return Database(container)

def main():
    db = cli_get_db()
    CLI(db).cmdloop()
