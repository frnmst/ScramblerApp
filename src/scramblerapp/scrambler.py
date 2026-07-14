# The Scrambler
# Copyright (c) 2023 Arctic Technology

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import json
import os
import pathlib
import re
import shlex
import subprocess
import sys

import cmd2
from platformdirs import PlatformDirs

from .utils.commoncmd import CommonCmd
from .utils.encryption import OpenSSLEncyptor
from .workflow import workflow


class Instance:

    def __init__(self):
        openssl = OpenSSLEncyptor.get_version()
        if openssl['status'] == 400:
            failure_msg1: str = '\n OpenSSL is required to run this app. Make sure you have OpenSSL installed.'
            failure_msg2: str = '\n Use command `openssl version` to check your openssl version.'
            raise Exception(openssl['message'] + ' ' + failure_msg1 + ' ' +
                            failure_msg2)

        self.version_text = openssl['message']
        self.raw = openssl['raw']

        self.app_paths = PlatformDirs('scramblerapp')
        self.settings_file: pathlib.Path = self.app_paths.user_config_path / 'config.json'

        self.set_settings()
        ok, message = self.load_settings()
        if not ok:
            print(f'Error: unable to load settings: {message}')
            sys.exit(1)

    def get_crypto_suite_mappings(self, encrypt: bool = True) -> str:
        """Map raw engine and version to uniform short outputs."""
        start: str
        if encrypt:
            match self.raw['engine']:
                case 'openssl':
                    start = 'ossl'
                case 'libressl':
                    start = 'lssl'
                case 'cryptography':
                    start = 'pycrypt'

            return '.'.join([start, self.raw['version']])
        else:
            return 'NAKED'

    def set_settings(self):
        # Get defaults.
        self.encrypted_file_suffix: str = self.get_crypto_suite_mappings(True)
        self.decrypted_file_suffix: str = self.get_crypto_suite_mappings(False)
        self.crypto_backend: str = 'openssl'

    def _is_valid_file_suffix(self, suffix: str) -> bool:
        # Avoid (/ o \), forbidden Windows chars or empty spaces and some
        # other special chars.
        pattern: str = r'^[^<>:"/\\|?*\s\.,]+$'
        if re.match(pattern, suffix):
            return True
        else:
            return False

    def _is_valid_crypto_backend(self, backend: str) -> bool:
        if backend in ['openssl', 'libressl', 'cryptography']:
            return True
        else:
            return False

    def load_settings(self) -> [bool, str]:
        self.app_paths.user_config_path.mkdir(parents=True, exist_ok=True)

        if self.settings_file.is_file():
            try:
                payload: str = self.settings_file.read_text(encoding='utf-8')
                data: dict[str] = json.loads(payload)

                self.decrypted_file_suffix = data.get(
                    'decrypted_file_suffix', self.decrypted_file_suffix)
                self.encrypted_file_suffix = data.get(
                    'encrypted_file_suffix', self.encrypted_file_suffix)
                self.crypto_backend = data.get('crypto_backend',
                                               self.crypto_backend)

                if not self._is_valid_file_suffix(self.decrypted_file_suffix):
                    return False, f'"{self.decrypted_file_suffix}" is not a valid decrypted file suffix'
                if not self._is_valid_file_suffix(self.encrypted_file_suffix):
                    return False, f'"{self.encrypted_file_suffix}" is not a valid encrypted file suffix'
                if not self._is_valid_crypto_backend(self.crypto_backend):
                    return False, f'"{self.crypto_backend} is not a valid crypto backend'

                return True, ''
            except Exception as e:
                return False, e
        else:
            # Use default settings.
            return True, 'file not found'

    def save_settings(self) -> [bool, str]:
        data: dict[str] = {
            'decrypted_file_suffix': self.decrypted_file_suffix,
            'encrypted_file_suffix': self.encrypted_file_suffix,
            'crypto_backend': self.crypto_backend,
        }

        try:
            # Bytes written.
            bts: int = self.settings_file.write_text(json.dumps(data),
                                                     encoding='utf-8')
            return True, str(bts)
        except Exception as e:
            return False, e


class BaseMenu(cmd2.Cmd):

    def __init__(self,
                 allowed_commands,
                 scrambler,
                 submenu_type: str,
                 commands_that_clear_screen: list[str] = []):
        super().__init__(include_py=False, include_ipy=False)
        self.my_commands = allowed_commands

        # App specific settings.
        self.scrambler = scrambler
        self.instance = Instance()
        self.working_directory: pathlib.Path = pathlib.Path.cwd()

        # Hide all built-in cmd2 commands.
        for cmd_name in self.get_all_commands():
            if cmd_name not in self.my_commands:
                self.hidden_commands.append(cmd_name)

        self._from_home_menu = True
        self.submenu_type: str = submenu_type
        self.commands_that_clear_screen: list[str] = commands_that_clear_screen

    def _clear_terminal(self):
        # Use 'cls' for Windows, 'clear' for Linux/macOS
        command = 'cls' if os.name == 'nt' else 'clear'
        subprocess.run(command, shell=True)

        # ANSI code alternative
        # self.poutput('\x1b[H\x1b[2J', end='')

    def precmd(self, line):
        sanitized: str = line.command.strip()
        command: str = sanitized.split()[0] if sanitized else ''

        if command in self.commands_that_clear_screen:
            self._clear_terminal()

        # precmd must return the line to pass it to the command executor.
        return line

    def clear_and_show_help(self,
                            menu_name: str = f'Scrambler App',
                            question: str = f'What would you like to do?'):
        self._clear_terminal()

        self.poutput(f'=== {menu_name} ===')
        self.poutput()

        if self.submenu_type == 'settings':
            # Use specific layout.
            self.poutput(f'Current Directory: {self.working_directory}')
            func = getattr(self, f'do_s')
            self.poutput(f'(s) {func.__doc__}')

            self.poutput()
            self.poutput(f'Selected Algorithm: {self.instance.version_text}')
            func_o = getattr(self, f'do_o')
            func_p = getattr(self, f'do_p')
            self.poutput(
                f'(o) {self.instance.version_text} (p) Python Cryptography')

            self.poutput()
            self.poutput(f'Encrypted File Suffix:')
            func_es = getattr(self, f'do_es')
            self.poutput(f'(es) {func_es.__doc__}')

            self.poutput()
            self.poutput(f'Decrypted File Suffix:')
            func_ds = getattr(self, f'do_ds')
            self.poutput(f'(ds) {func_ds.__doc__}')

            self.poutput()
            self.poutput(f'Learn more')
            func = getattr(self, f'do_a')
            self.poutput(f'(a) {func.__doc__}')

        else:
            self.poutput(question)

            for cmd_name in self.my_commands:
                if cmd_name == 'help':
                    continue
                func = getattr(self, f'do_{cmd_name}')
                # Read help from docstrings.
                self.poutput(f'{"(" + cmd_name + ")":<6} {func.__doc__}')

        self.poutput()

    def onecmd_plus_hooks(self, line: str, *args, **kwargs) -> bool:
        """CLI Entry point."""
        # See
        # https://cmd2.readthedocs.io/en/latest/api/cmd/#cmd2.Cmd.onecmd_plus_hooks
        if not line.strip():
            # User did not type a command: clear the terminal
            self.clear_and_show_help()

            # Always process commands, do not quit.
            return False

        # Normal execution.
        return super().onecmd_plus_hooks(line, *args, **kwargs)

    def do_help(self, args):
        """Show available commands and descriptions."""
        self.clear_and_show_help()

    def postcmd(self, stop, line):
        """Re-print help menu after each command."""
        self.clear_and_show_help()
        return stop

    def default(self, statement):
        self.perror(f"Invalid selection: '{statement.command}'. Try again.")
        if self._from_home_menu:
            self.read_input('\nPress Enter to continue...')


class SettingsSubMenu(BaseMenu):

    def __init__(self,
                 scrambler,
                 parent,
                 working_directory: pathlib.Path = pathlib.Path.cwd()):
        super().__init__(allowed_commands=[
            'b', 'q', 'o', 'p', 'es', 'ds', 'a', 'help', 's'
        ],
                         scrambler=scrambler,
                         submenu_type='settings',
                         commands_that_clear_screen=['a'])

        self.prompt = '> '
        self.working_directory = working_directory
        self.parent = parent
        self._from_home_menu = False

    def clear_and_show_help(self):
        super().clear_and_show_help('Settings')

    def _change_suffix(self, encrypt: bool = True):
        adjective: str = 'decrypt'
        if encrypt:
            adjective = 'encrypt'

        suffix: str = self.read_input(
            f"Set a new {adjective}ed file suffix: ").strip()
        if suffix:
            if not self.instance._is_valid_file_suffix(suffix):
                self.perror(
                    f'error: "{suffix}" is not a valid {adjective}ed file suffix'
                )
                return

            if encrypt:
                self.instance.encrypted_file_suffix = suffix
            else:
                self.instance.decrypted_file_suffix = suffix

            ok: bool
            message: str
            ok, message = self.instance.save_settings()
            if ok:
                self.psuccess('settings saved')
            else:
                self.perror(f'error saving settings:\n  {message}')
        else:
            self.perror('error: suffix cannot be empty')
            return

    def postcmd(self, stop, line):
        if stop:
            return True

        self.read_input('\nPress Enter to continue...')
        self.clear_and_show_help()
        return stop

    def do_b(self, args):
        """Go back to the Home menu."""
        return True

    def do_q(self, args):
        """Go back to the Home menu."""
        return self.do_b(args)

    def do_s(self, args: str):
        """Set Directory"""
        path = args.strip() if args else ''

        if not path:
            self.pwarning(
                'HINT: Press\n  <TAB> to browse and autocomplete\n  "../" + <TAB> to browse directories one level up\n  "." to select the current directory'
            )
            try:
                path = self.read_input(
                    prompt='Select a new working directory: ',
                    completer=self.complete_s)
            except (EOFError, KeyboardInterrupt):
                self.pwarning('\nAborted.')
                return

        path = path.strip()
        if not path:
            return

        new_path: pathlib.Path = pathlib.Path(path).expanduser().resolve()

        if not new_path.exists():
            self.perror(f"Error: Path '{new_path}' does not exists.")
        elif not new_path.is_dir():
            self.perror(f"Error: '{new_path}' is not a directory")
        else:
            self.working_directory = new_path
            os.chdir(str(new_path))

        if self.parent:
            self.parent.working_directory = new_path

    def complete_s(self, *args, **kwargs):
        """Only show directories."""
        text, line, begidx, endidx = args[-4:]

        directory_filter = lambda p: pathlib.Path(p).is_dir()
        return self.path_complete(text,
                                  line,
                                  begidx,
                                  endidx,
                                  path_filter=directory_filter)

    def do_o(self, args):
        """Use system's OpenSSL/LibreSSL binary."""
        self.poutput('DUMMY select OpenSSL, exclude Cryptography...')

    def do_p(self, args):
        """Use Python Cryptography library."""

    def do_a(self, args):
        """About"""
        self.poutput('DUMMY about, just print on screen...')

    def do_ds(self, args):
        """Set decrypted suffix"""
        self._change_suffix(encrypt=False)

    def do_es(self, args):
        """Set encrypted suffix"""
        self._change_suffix(encrypt=True)


class CryptoSubMenu(BaseMenu):

    def __init__(self,
                 scrambler,
                 encrypt: bool = True,
                 working_directory: pathlib.Path = pathlib.Path.cwd()):
        super().__init__(allowed_commands=['1', '2', '3', '4'],
                         scrambler=scrambler,
                         submenu_type='encrypt' if encrypt else 'decrypt',
                         commands_that_clear_screen=['1', '2', '3', '4'])

        self.working_directory = working_directory

        # Hack to override the docstring.
        self.do_c.__func__.__doc__ = 'Columns in a DataFrame'
        self.do_d.__func__.__doc__ = 'All files in directory'
        self.do_f.__func__.__doc__ = 'A file'
        self.do_m.__func__.__doc__ = 'A message'

        self.prompt = '> '
        self.encrypt = encrypt
        self._from_home_menu = False

    def clear_and_show_help(self):
        super().clear_and_show_help(
            menu_name='Encrypt' if self.encrypt else 'Decrypt',
            question=
            f'What would you like to {"encrypt" if self.encrypt else "decrypt"}?'
        )

    def postcmd(self, stop, line):
        if stop:
            # Quit immediately if user wants to go back.
            if line.command.strip() not in ['b', 'q']:
                self.read_input('\nPress Enter to continue...')
            return True

        self.read_input('\nPress Enter to continue...')
        self.clear_and_show_help()
        return stop

    def do_b(self, args):
        """Go back to the Home menu"""
        return True

    def do_m(self, args):
        """Cipher/Decypher message."""
        wf = workflow.MessageCryptoWorkflow(menu_instance=self)
        return wf.start()

    def do_f(self, args):
        """Cipher/Decypher files."""
        wf = workflow.FileCryptoWorkflow(
            menu_instance=self,
            resource_type='file',
            working_directory=self.working_directory)
        return wf.start(args)

    def complete_f(self, text, line, begidx, endidx):
        """Autocomplete paths."""
        wf = workflow.FileCryptoWorkflow(
            menu_instance=self,
            resource_type='file',
            working_directory=self.working_directory)
        return wf.complete(text, line, begidx, endidx)

    def do_d(self, args):
        """Cipher/Decypher directories."""
        wf = workflow.FileCryptoWorkflow(
            menu_instance=self,
            resource_type='directory',
            working_directory=self.working_directory)
        return wf.start(args)

    def complete_d(self, text, line, begidx, endidx):
        """Autocomplete paths."""
        wf = workflow.FileCryptoWorkflow(
            menu_instance=self,
            resource_type='directory',
            working_directory=self.working_directory)
        return wf.complete(text, line, begidx, endidx)

    def do_c(self, args):
        """Cipher/Decypher dataframe columns."""
        self.pwarning('Feature coming soon')

    # Aliases.
    do_1 = do_m
    do_2 = do_f
    do_3 = do_d
    do_4 = do_c
    do_q = do_b


class ScramblerAppHome(BaseMenu):
    """Main App menu."""

    def __init__(self, scrambler):
        super().__init__(
            allowed_commands=['e', 'd', 'ls', 'pwd', 's', 'q', 'help'],
            scrambler=scrambler,
            submenu_type='home',
            commands_that_clear_screen=['pwd', 'ls'])
        self.prompt = '> '
        self.working_directory = pathlib.Path.cwd()
        self.clear_and_show_help()
        self.commands_that_clear_screen: list[str] = ['pwd', 'ls']

    def clear_and_show_help(self):
        super().clear_and_show_help('Scrambler App')

    def do_q(self, args):
        """Quit"""
        self.psuccess('Goodbye!')
        return True

    def do_pwd(self, args):
        """Show current directory"""
        self.poutput(f'Current directory:')
        self.poutput()
        self.poutput(f'{self.working_directory}')
        self.read_input('\nPress Enter to continue...')

    def do_ls(self, args):
        """List files"""
        self.poutput(f'Directory listing:')
        self.poutput()
        [self.poutput(l) for l in CommonCmd.ls(self.working_directory)]
        self.read_input('\nPress Enter to continue...')

    def do_s(self, args):
        """Settings"""
        sub_menu = SettingsSubMenu(
            scrambler=self.scrambler,
            parent=self,
            working_directory=self.working_directory,
        )

        sub_menu.clear_and_show_help()
        # Don't exit this sub-menu unless the user types 'b' (back).
        sub_menu.cmdloop()

    def do_e(self, args):
        """Encrypt"""
        sub_menu = CryptoSubMenu(
            scrambler=self.scrambler,
            encrypt=True,
            working_directory=self.working_directory,
        )

        sub_menu.clear_and_show_help()
        # Don't exit this sub-menu unless the user types 'b' (back).
        sub_menu.cmdloop()

    def do_d(self, args):
        """Decrypt"""
        sub_menu = CryptoSubMenu(
            scrambler=self.scrambler,
            encrypt=False,
            working_directory=self.working_directory,
        )

        sub_menu.clear_and_show_help()
        # Don't exit this sub-menu unless the user types 'b' (back).
        sub_menu.cmdloop()
