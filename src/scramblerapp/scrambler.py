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

    def set_settings(self):
        self.encrypted_file_suffix: str = f'{self.raw["engine"]}-{self.raw["version"].replace(".", "_")}-enc'
        self.decrypted_file_suffix: str = f'NAKED'
        self.directory_depth: int = 0
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

                self.directory_depth = data.get('directory_depth',
                                                self.directory_depth)
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
            'directory_depth': self.directory_depth,
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

    def __init__(self, allowed_commands, scrambler):
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

    def _clear_terminal(self):
        # Use 'cls' for Windows, 'clear' for Linux/macOS
        command = 'cls' if os.name == 'nt' else 'clear'
        subprocess.run(command, shell=True)

        # ANSI code alternative
        # self.poutput('\x1b[H\x1b[2J', end='')

    def clear_and_show_help(self):
        menu_closer_len: int = 8 + len(self.__class__.__name__)

        self._clear_terminal()

        self.poutput(f"=== {self.__class__.__name__} ===")
        self.poutput('Available commands:')

        for cmd_name in sorted(self.my_commands):
            if cmd_name == 'help':
                continue
            func = getattr(self, f"do_{cmd_name}")
            # Read help from docstrings.
            self.poutput(f'  {cmd_name:<5} - {func.__doc__}')

        self.poutput()
        self.poutput(f'Available crypto suites:')
        self.poutput(f' [*]      {self.instance.version_text}')
        self.poutput(f' [ ]      Python Cryptography')
        self.poutput()
        self.poutput(f'Current working directory:')
        self.poutput(f' {self.working_directory}')
        self.poutput(menu_closer_len * '=')

    def do_help(self, args):
        """Show available commands and descriptions."""
        self.clear_and_show_help()

    def postcmd(self, stop, line):
        """Re-print help menu after each command."""
        if not stop:
            self.read_input('\nPress Enter to continue...')
            self.clear_and_show_help()
        return stop

    def default(self, statement):
        self.perror(f"Invalid selection: '{statement.command}'. Try again.")


class SettingsSubMenu(BaseMenu):

    def __init__(self,
                 scrambler,
                 working_directory: pathlib.Path = pathlib.Path.cwd()):
        super().__init__(
            allowed_commands={
                'b', 'q', 'o', 'p', 'es', 'ds', 'd', 'a', 'help'
            },
            scrambler=scrambler,
        )

        self.prompt = 'settings > '
        self.working_directory = working_directory

    def _change_suffix(self, encrypt: bool = True):
        adjective: str = 'decrypt'
        if encrypt:
            adjective = 'encrypt'

        suffix: str = self.read_input(
            f"Set a new {adjective}ed file suffix: ").strip()
        if suffix:
            if not self.instance._is_valid_file_suffix(suffix):
                self.perror(
                    f'"{suffix}" is not a valid {adjective}ed file suffix')
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

    def do_b(self, args):
        """Go back to the Home menu."""
        self.psuccess('Returning to main menu...')
        return True

    def do_q(self, args):
        """Go back to the Home menu."""
        return self.do_b(args)

    def do_o(self, args):
        """Use system's OpenSSL/LibreSSL binary."""
        self.poutput('DUMMY select OpenSSL, exclude Cryptography...')

    def do_p(self, args):
        """Use Python Cryptography library."""
        self.poutput('DUMMY select cryptography, exclude OpenSSL...')

    def do_a(self, args):
        """About."""
        self.poutput('DUMMY about, just print on screen...')

    def do_d(self, args):
        """Directory depth."""
        self.poutput('Must be an int >= 0')

    def do_ds(self, args):
        """Change decrypted file suffix."""
        self._change_suffix(encrypt=False)

    def do_es(self, args):
        """Change encrypted file suffix."""
        self._change_suffix(encrypt=True)


class CryptoSubMenu(BaseMenu):

    def __init__(self,
                 scrambler,
                 encrypt: bool = True,
                 working_directory: pathlib.Path = pathlib.Path.cwd()):
        super().__init__(
            allowed_commands={'c', 'b', 'm', 'q', 'f', 'd', 'help'},
            scrambler=scrambler,
        )

        self.working_directory = working_directory

        if encrypt:
            # Hack to override the docstring.
            self.do_c.__func__.__doc__ = 'Encrypt dataframe columns.'
            self.do_d.__func__.__doc__ = 'Encrypt directory.'
            self.do_f.__func__.__doc__ = 'Encrypt file.'
            self.do_m.__func__.__doc__ = 'Encrypt message.'
            self.prompt = 'encrypt > '
        else:
            self.do_c.__func__.__doc__ = 'Decrypt dataframe columns.'
            self.do_d.__func__.__doc__ = 'Decrypt directory.'
            self.do_f.__func__.__doc__ = 'Decrypt file.'
            self.do_m.__func__.__doc__ = 'Decrypt message.'
            self.prompt = 'decrypt > '

        self.encrypt = encrypt

    def do_b(self, args):
        """Go back to the Home menu."""
        self.psuccess('Returning to main menu...')
        return True

    def do_q(self, args):
        """Go back to the Home menu."""
        return self.do_b(args)

    def do_m(self, args):
        """Cipher/Decypher message."""
        wf = workflow.MessageCryptoWorkflow(menu_instance=self)
        wf.start()

    def do_f(self, args):
        """Cipher/Decypher files."""
        wf = workflow.FileCryptoWorkflow(
            menu_instance=self,
            resource_type='file',
            working_directory=self.working_directory)
        wf.start(args)

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
        wf.start(args)

    def complete_d(self, text, line, begidx, endidx):
        """Autocomplete paths."""
        wf = workflow.FileCryptoWorkflow(
            menu_instance=self,
            resource_type='directory',
            working_directory=self.working_directory)
        return wf.complete(text, line, begidx, endidx)

    def do_c(self, args):
        """Cipher/Decypher dataframe columns."""


class ScramblerAppHome(BaseMenu):
    """Main App menu."""

    def __init__(self, scrambler):
        super().__init__(
            allowed_commands={'s', 'e', 'd', 'q', 'cd', 'help'},
            scrambler=scrambler,
        )
        self.prompt = 'command > '
        self.working_directory = pathlib.Path.cwd()
        self.clear_and_show_help()

    def do_q(self, args):
        """Quit the application."""
        self.psuccess('Goodbye!')
        return True

    def do_s(self, args):
        """Open the settings sub-menu."""
        sub_menu = SettingsSubMenu(
            scrambler=self.scrambler,
            working_directory=self.working_directory,
        )

        sub_menu.clear_and_show_help()
        # Don't exit this sub-menu unless the user types 'b' (back).
        sub_menu.cmdloop()

    def do_cd(self, args: str):
        """Set working directory."""
        path = args.strip() if args else ''

        if not path:
            self.pwarning(
                'HINT: Press\n  <TAB> to browse and autocomplete\n  "../" + <TAB> to browse directories one level up\n  "." to select the current directory'
            )
            try:
                path = self.read_input(
                    prompt='Select a new working directory: ',
                    completer=self.complete_cd)
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

    def complete_cd(self, *args, **kwargs):
        """Only show directories."""
        text, line, begidx, endidx = args[-4:]

        directory_filter = lambda p: pathlib.Path(p).is_dir()
        return self.path_complete(text,
                                  line,
                                  begidx,
                                  endidx,
                                  path_filter=directory_filter)

    def do_e(self, args):
        """Open the encryption sub-menu."""
        sub_menu = CryptoSubMenu(
            scrambler=self.scrambler,
            encrypt=True,
            working_directory=self.working_directory,
        )

        sub_menu.clear_and_show_help()
        # Don't exit this sub-menu unless the user types 'b' (back).
        sub_menu.cmdloop()

    def do_d(self, args):
        """Open the decryption sub-menu."""
        sub_menu = CryptoSubMenu(
            scrambler=self.scrambler,
            encrypt=False,
            working_directory=self.working_directory,
        )

        sub_menu.clear_and_show_help()
        # Don't exit this sub-menu unless the user types 'b' (back).
        sub_menu.cmdloop()
