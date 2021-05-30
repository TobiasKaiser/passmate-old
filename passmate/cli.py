from .db import Database
from .container import DatabaseContainer
import getpass
import argparse
from .hierarchy import PathHierarchy

from prompt_toolkit import prompt, PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.shortcuts import CompleteStyle




from prompt_toolkit.filters import completion_is_selected, has_completions
from prompt_toolkit.key_binding import KeyBindings



class PromptCompleter(Completer):
    def __init__(self, cli):
        super().__init__()
        self.cli = cli
        self.hier = PathHierarchy(cli.db)

    def get_completions(self, document, complete_event):
        for comp in self.path_complete(document, complete_event):
            yield comp

    def path_complete(self, document, complete_event):
        start_idx=document.text.rfind("/")
        var=document.text[start_idx+1:]
        cur_dir = self.hier.root
        if start_idx>=0:
            for dirname in document.text.split("/")[:-1]:
                try:
                    cur_dir = cur_dir.subdirs[dirname]
                except KeyError:
                    return
        comp_paths = list(map(lambda d:d+"/", cur_dir.subdirs.keys()))
        comp_recs = list(cur_dir.records.keys())
        complete = comp_paths+comp_recs
        for c in complete:
            if c.startswith(var):
                yield Completion(c, start_position=-len(var))

class CLI:
    def key_bindings(self):
        key_bindings = KeyBindings()

        @key_bindings.add("enter", filter=has_completions & ~completion_is_selected)
        def _(event):
            event.current_buffer.go_to_completion(0)
            event.current_buffer.complete_state = None

        @key_bindings.add("enter", filter=completion_is_selected)
        def _(event):
            event.current_buffer.complete_state = None
        return key_bindings

    def __init__(self, db):
        self.db = db

    def run(self):
        running = True
        session = PromptSession(key_bindings=self.key_bindings(), complete_style=CompleteStyle.MULTI_COLUMN)

        while running:
            my_completer=PromptCompleter(self)
            text = session.prompt('passmate> ', completer=my_completer,
              complete_while_typing=True)




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
    CLI(db).run()

    
