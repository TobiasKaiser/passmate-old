from .db import Database, Record
from .container import DatabaseContainer
import getpass
import argparse
import collections
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
        # Complete only at end of line:
        if document.cursor_position!=len(document.text):
            return

        text = document.text

        # Complete command names
        if not " " in text:
            for c in self.cli.commands:
                if not c.context_check(self.cli):
                    continue
                if not c.cmd:
                    continue
                if c.cmd.startswith(text):
                    yield  Completion(c.cmd, start_position=-len(text), style='fg:ansired')

        default_cmd = None

        # Call command handlers if applicable
        for c in self.cli.commands:
            if not c.context_check(self.cli):
                continue
            if not c.cmd:
                assert not default_cmd
                default_cmd = c
                continue
            if text.startswith(c.cmd+" "):
                if c.completion_handler:
                    for comp in c.completion_handler(self, text[len(c.cmd)+1:]):
                        yield comp
                return

        # Call default handler else
        if default_cmd and default_cmd.completion_handler:
            for comp in default_cmd.completion_handler(self, text):
                yield comp

    def handle_path(self, text):

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
                yield Completion(record, start_position=-len(var))
    
    def handle_field_name(self, text):
        return

class CLI:

    Command = collections.namedtuple('Command', ['cmd', 'context_check', 'handler', 'completion_handler'])

    def cmd_return(self, args):
        self.cur_path = None

    def cmd_exit(self, args):
        return True

    def cmd_show(self, args):
        if len(args)>0:
            self.cur_path = args

        if not (self.cur_path in self.db.records):
            print("No record at current path.")
            return

        rec = self.db.records[self.cur_path]
        maxlen = max(map(len, rec.fields.keys()))
        for name, values in rec.fields.items():
            print(f"{name:>{maxlen}}: {values[0]}")
            for v in values[1:]:
                nothing=""
                print(f"{nothing:>{maxlen}}> {v}")

    # Todo

    def cmd_set(self, args):
        print(f"todo: set {args}")

    def cmd_unset(self, args):
        print(f"todo: unset {args}")

    def cmd_rename(self, args):
        print(f"todo: unset {args}")

    def cmd_new(self, args):
        if len(args)==0:
            print("?")

        if (args in self.db.records):
            print("Record already exists.")
            return

        self.cur_path = args

        self.db.records[self.cur_path] = Record(self.db)

    def cmd_del(self, args):
        print(f"todo: new {args}")

    def cmd_chpass(self, args):
        print(f"todo: chpass {args}")

    def cmd_save(self, args):
        if len(args)>0:
            print("?")
            retun


        print(self.db.get_updates())



    commands = [
        # Commands in root mode
        Command(None,     lambda cli: not cli.cur_path, cmd_show, PromptCompleter.handle_path),

        # Commands in leaf mode
        Command("set",    lambda cli:     cli.cur_path, cmd_set, PromptCompleter.handle_field_name),
        Command("unset",  lambda cli:     cli.cur_path, cmd_unset, PromptCompleter.handle_field_name),
        Command("rename", lambda cli:     cli.cur_path, cmd_rename, PromptCompleter.handle_path),
        Command("return", lambda cli:     cli.cur_path, cmd_return, None),
        Command(None,     lambda cli:     cli.cur_path, cmd_return, None),

        # Commands that work always
        Command("show",   lambda cli: True,             cmd_show, PromptCompleter.handle_path),
        Command("save",   lambda cli: True,             cmd_save, None),
        Command("exit",   lambda cli: True,             cmd_exit, None),
        Command("new",    lambda cli: True,             cmd_new, PromptCompleter.handle_path),
        Command("del",    lambda cli: True,             cmd_del, PromptCompleter.handle_path),
        Command("chpass", lambda cli: True,             cmd_chpass, None),

    ]

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

    def handle_cmd(self, text):
        default_cmd = None

        # Call command handlers if applicable
        for c in self.commands:
            if not c.context_check(self):
                continue
            if not c.cmd:
                assert not default_cmd
                default_cmd = c
                continue
            if text.startswith(c.cmd):
                return c.handler(self, text[len(c.cmd)+1:])

        # Call default handler else
        if default_cmd:
            return default_cmd.handler(self, text)

    def run(self):
        running = True
        session = PromptSession(key_bindings=self.key_bindings(), complete_style=CompleteStyle.READLINE_LIKE)

        while running:
            my_completer=PromptCompleter(self)
            pathinfo=""
            if self.cur_path:
                pathinfo=":"+self.cur_path
            text = session.prompt(f'passmate{pathinfo}> ', completer=my_completer, complete_while_typing=True)

            if self.handle_cmd(text):
                running=False




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

    

