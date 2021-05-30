from .db import Database
from .container import DatabaseContainer
import getpass
import argparse
import cmd
from .hierarchy import PathHierarchy
from termcolor import colored

class CLI(cmd.Cmd):


    def __init__(self, db):
        super().__init__()
        self.cur_path = ""
        self.db = db

    @property
    def prompt(self):
        return f"pmate:{self.cur_path}>"
        

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

    def do_ls(self, arg):
        h = PathHierarchy(self.db, self.cur_path)
        dirs, recs = h.listdir()
        i=1
        for d in dirs:
            colored_d = colored(d, "blue", attrs=["bold"])
            print(f"{i:>3} {colored_d}/")
            i+=1
        for r in recs:
            print(f"{i:>3} {r}")
            i+=1

    def do_show(self, arg):
        if self.cur_path in self.db.records:
            rec = self.db.records[self.cur_path]
            maxlen = max(map(len, rec.fields.keys()))
            for name, values in rec.fields.items():
                name_colored = colored(name, "green")
                print(f"{name_colored:>{maxlen+9}}: {values[0]}")
                for v in values[1:]:
                    nothing=""
                    print(f"{nothing:>{maxlen}}> {v}")

    def do_cd(self, arg):
        return self.default(arg+"/")

    def default(self, arg):
        h = PathHierarchy(self.db, self.cur_path)
        self.cur_path = h.chdir(arg)

    def do_open(self, arg):
        pass

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
