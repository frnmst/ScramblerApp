import getpass
import pathlib
import re
from typing import Type, Union

from ..dircrawler.filemodder import FileModder


class Workflow:

    def __init__(self, menu_instance):
        self.menu = menu_instance
        self.encrypt: bool = self.menu.encrypt
        self.keyword: str = 'Encrypt' if self.encrypt else 'Decrypt'

    def validate_password(self) -> str:
        done: bool = False
        attempts: int = 0
        max_attempts: int = 1
        while not done and attempts <= max_attempts:
            prompt_msg = 'Password (>10 chars required): ' if self.encrypt else 'Decryption Password: '
            pwd = getpass.getpass(prompt_msg)

            if not pwd:
                pwd = ''

            if self.encrypt and len(pwd) <= 10:
                self.menu.perror(
                    'Error: Password must be strictly greater than 10 characters.'
                )
                attempts += 1

            elif self.encrypt:
                confirm_pwd = getpass.getpass('Confirm Password: ')
                if pwd != confirm_pwd:
                    self.menu.perror(
                        'Error: Passwords do not match. Please try again.')
                    attempts += 1

                    # Reset password if they do not match.
                    pwd = ''
                else:
                    done = True

            elif not self.encrypt:
                if pwd:
                    done = True
                else:
                    self.menu.perror('Error: Password cannot be empty')

        return pwd

    def get_password(self) -> str:
        password: str = self.validate_password()
        if password:
            return password
        else:
            self.menu.perror('Operation cancelled due to password failure.')
            return ''

    def print_option_heading(self, question_prefix: str):
        self.menu.poutput(f'=== {self.keyword} ===')
        self.menu.poutput()
        self.menu.poutput(f'{question_prefix} {self.keyword.lower()}?')
        self.menu.poutput()


class FileCryptoWorkflow(Workflow):

    def __init__(self, menu_instance, resource_type: str,
                 working_directory: pathlib.Path):
        super().__init__(menu_instance)

        # Type of resource to handle: 'file', 'directory'.
        self.resource_type: str = resource_type
        self.working_directory: pathlib.Path = working_directory
        self.naked = True if (not self.encrypt
                              and self.resource_type == 'file') else False

    def get_destination_files_suffix(self) -> dict[list[str]]:
        if self.encrypt:
            self.menu.pwarning(
                f'[NOTE]: new files will include this suffix:\n  {self.menu.instance.encrypted_file_suffix}'
            )
        else:
            self.menu.pwarning(
                f'[NOTE]: new files will include this suffix:\n  {self.menu.instance.decrypted_file_suffix}'
            )

        return {
            'encrypt': [self.menu.instance.encrypted_file_suffix],
            'decrypt': [
                self.menu.instance.decrypted_file_suffix,
                self.menu.instance.decrypted_file_suffix
            ],
        }

    def filter_source_files_by_extension(self) -> Union[str, Type[None]]:
        self.menu.pwarning(
            f'You may specify a file type to {self.keyword.lower()}. Leave blank for default .txt files'
        )
        self.menu.pwarning(
            f'Use * to {self.keyword.lower()} all files regardless of type (this can be dangerous)'
        )

        raw_extension: str = self.menu.read_input(
            'Filter files by extension [optional]: ')
        return FileModder.format_ext(raw_extension)

    def keep_original_files(self) -> bool:
        delete_original_files: str = self.menu.read_input(
            'Delete original files (Y/n)? ')
        keep_orig: bool = True
        if delete_original_files in ['y', 'Y', '']:
            keep_orig = False
        return keep_orig

    def start(self, args: str):
        # args contains the file or directory path.
        path: str = args.strip() if args else ''

        self.print_option_heading(
            question_prefix=f'Which {self.resource_type} do you want to')

        if not path:
            self.menu.pwarning('Press <TAB> to browse.')
            self.menu.poutput()
            try:
                # Interactive prompt.
                path = self.menu.read_input(prompt='> ',
                                            completer=self.complete)
            except (EOFError, KeyboardInterrupt):
                self.menu.perror('\nAborted.')
                return False

        path = path.strip()
        if not path:
            self.menu.perror(
                f"Error: Specify a valid path. Press TAB to browse.")
            return False

        p_path: pathlib.Path = pathlib.Path(path).expanduser().resolve()

        if not p_path.exists():
            self.menu.perror(f'Error: Path "{p_path}" does not exists.')
            return False

        password: str
        if self.resource_type == 'file':
            if p_path.is_dir():
                self.menu.perror(
                    f'"{p_path}" is a directory. Select a file instead.')
                return
            elif p_path.is_file():
                confirmation: str = self.menu.read_input(
                    f'Are you sure you want to {self.keyword.lower()} file "{p_path}" (Y/n)? '
                )
                if confirmation in ['y', 'Y', '']:

                    crypto_file_extensions = self.get_destination_files_suffix(
                    )

                    keep_orig: bool = self.keep_original_files()

                    password = self.get_password()
                    if not password:
                        return False

                    result = self.menu.scrambler.encrypt_file(
                        password,
                        str(p_path),
                        decrypt=not self.encrypt,
                        keep_org=keep_orig,
                        naked=self.naked,
                        tag_options=crypto_file_extensions,
                    )
                    if result['status'] == 200:
                        self.menu.psuccess(result['message'])
                    else:
                        self.menu.perror(result['message'])
                else:
                    self.menu.pwarning('Exited, no action taken.')
                    return False
        elif self.resource_type == 'directory':
            if p_path.is_file():
                self.menu.perror(
                    f'"{p_path}" is a file. Select a directory instead.')
                return
            elif p_path.is_dir():
                extension = self.filter_source_files_by_extension()

                # Tag options.
                crypto_file_extensions = self.get_destination_files_suffix()

                keep_orig: bool = self.keep_original_files()

                if extension is None:
                    confirmation_message = f'Are you sure you want to {self.keyword.lower()} all files of all types'
                else:
                    confirmation_message = f'Are you sure you want to {self.keyword.lower()} all files with extension {extension}'

                confirmation_message = f'{confirmation_message} in "{p_path}" (Y/n)? '
                confirmation = self.menu.read_input(confirmation_message)

                if confirmation in ['y', 'Y', '']:
                    password = self.get_password()
                    if not password:
                        return

                    # Mock:
                    #   result = {'status': 200, 'message': 'OK', 'output': ['ok 0', 'ok 1']}
                    result = self.menu.scrambler.encrypt_all_files(
                        password,
                        str(p_path),
                        decrypt=not self.encrypt,
                        extension=extension,
                        keep_org=keep_orig,
                        naked=self.naked,
                        tag_options=crypto_file_extensions,
                    )
                    if result['status'] == 200:
                        for out in result['output']:
                            self.menu.psuccess(out)
                    else:
                        self.menu.perror(result['message'])
                else:
                    self.menu.pwarning('Exited, no action taken.')
                    return False
        else:
            self.menu.perror(
                f'Error: unknown "{self.resource_type}" resource type')
            return False

        return True

    def complete(self, *args, **kwargs):
        text, line, begidx, endidx = args[-4:]

        if self.resource_type == 'directory':
            resource_filter = lambda p: pathlib.Path(p).is_dir()
        else:
            # Directories need to be shown in file selection as well.
            resource_filter = None

        return self.menu.path_complete(text,
                                       line,
                                       begidx,
                                       endidx,
                                       path_filter=resource_filter)


class MessageCryptoWorkflow(Workflow):

    def __init__(self, menu_instance):
        super().__init__(menu_instance)

    def _clean_base64_payload(self, message: str) -> str:
        r"""Match of a Base64 string without spaces of at least 16 chars."""
        base64_pattern = r'(?:^|\s)([A-Za-z0-9+/]{16,}={0,2})(?=$|\s)'
        match = re.search(base64_pattern, message)
        if match:
            return match.group(1)
        return ''

    def start(self) -> bool:
        self.print_option_heading(
            self, question_prefix='What is the message you want to')

        message: str = self.menu.read_input('Input your message: ')
        if not message.strip():
            self.menu.perror('Error: Message cannot be empty. Exited.')
            return False

        if not self.encrypt:
            message = self._clean_base64_payload(message)
            if not message:
                self.menu.perror('Error: not a valid base64 payload')
                return False

        self.menu.poutput()
        password: str = self.get_password()
        if not password:
            return False

        result: dict = self.menu.scrambler.encrypt_msg(password, message,
                                                       not self.encrypt)

        self.menu._clear_terminal()
        self.menu.poutput(f'=== {self.keyword} ===')
        self.menu.poutput()

        if result['status'] == 200:
            self.menu.poutput('Operation completed.')
        else:
            self.menu.perror(result['message'])
            return False

        self.menu.poutput()
        if self.encrypt:
            self.menu.poutput(
                f'{self.menu.instance.get_crypto_suite_mappings()}: {result["output"]}'
            )
        else:
            self.menu.poutput(f'secret: {result["output"]}')

        return True
