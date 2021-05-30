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


    def complete(self, text, command_handlers, default_handler):
        if not " " in text:
            for c in command_handlers.keys():
                if c.startswith(text):
                    yield  Completion(c, start_position=-len(text), style='fg:ansired')

        for cmd, handler in command_handlers.items():
            if text.startswith(cmd+" "):
                if handler:
                    for comp in handler(text[len(cmd)+1:]):
                        yield comp
                return

        for comp in default_handler(text):
            yield comp

    def get_completions(self, document, complete_event):
        # Complete only at end of line:
        if document.cursor_position!=len(document.text):
            return

        if self.cli.cur_path:
            pass
        else:
            for comp in self.complete(document.text,
                {
                    "new":self.path_handler,
                    "chpass":None,
                },
                default_handler=self.path_handler):
                yield comp


    def path_handler(self, text):

        start_idx=text.rfind("/")

        var=text[start_idx+1:]
        cur_dir = self.hier.root
        if start_idx>=0:
            for dirname in text.split("/")[:-1]:
                try:
                    cur_dir = cur_dir.subdirs[dirname]
                except KeyError:
                    return
        for subdir in cur_dir.subdirs.keys():
            subdir=subdir+"/"
            if subdir.startswith(var):
                yield Completion(subdir, start_position=-len(var), style='fg:ansiblue')
        for record in cur_dir.records.keys():
            if record.startswith(var):
                yield Completion(record, start_position=-len(var), style='fg:ansiblack')
            
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
        self.cur_path=None

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

    
