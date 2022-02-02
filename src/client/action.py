#!/usr/bin/env python3
"""Action module to support client functionality."""

from os import getcwd, chdir, listdir, path, remove, mkdir
from logging import exception, basicConfig, DEBUG
from socket import AF_INET, SOCK_STREAM, socket, error

from packet import Packet
from packetmetadata import UserReply, RmReply, LsReply, GetReply, MkdirReply, \
    PutReply

LOG_FILE = 'debug.out'
basicConfig(filename=LOG_FILE, level=DEBUG)

DEFAULT_DIR = 'test/client/'
MAX_USER_LEN = 20
MAX_PASS_LEN = 30


class Events:
    """Events class that performs network/file functions."""

    mtu = 2048
    safe_path = ''

    @classmethod
    def generate_sock(cls, ip_addr, port):
        """Generates a socket and attemps to connect to server."""
        try:
            client_sock = socket(AF_INET, SOCK_STREAM)
            print("[~] Connecting...")
            client_sock.settimeout(5.0)
            client_sock.connect((ip_addr, port))
            client_sock.settimeout(None)

        except ConnectionRefusedError:
            print(f'[-] Failed to connect to {ip_addr}:{port}\n')
            exception(f'[-] Failed to connect to {ip_addr}:{port}\n')
            raise

        except error as e_err:
            print(f'[-] Connect timed out {ip_addr}:{port}\n')
            exception(f'[-] Connect timed out {ip_addr}:{port}\n')
            raise SystemExit from e_err

        except KeyboardInterrupt:
            print("CTRL_C")
            raise

        except OverflowError as e_err:
            print("[-] Port must be 0-65535")
            raise SystemExit from e_err

        except BaseException as e_err:
            print("[-] General error: ", e_err)
            raise SystemExit from e_err

        else:
            print(f'[+] Connected to: {ip_addr}:{port}')

            return client_sock

    @classmethod
    def user_activity(cls, client_sock, request_packet):
        """Network activity for client cmds inputed from the user."""

        packet = Packet()

        reply = {1: UserReply(),
                 2: RmReply(),
                 3: LsReply(),
                 4: GetReply(),
                 5: MkdirReply(),
                 6: PutReply()}

        user_metadata = reply[request_packet[0]]

        try:
            # Send USER cmd to server.
            client_sock.sendall(request_packet)

            recv_data = None
            client_sock.settimeout(3.1)  # timeout is over max client timeout.
            recv_data = client_sock.recv(Events.mtu)
            client_sock.settimeout(None)

            if recv_data is None:
                print("[-] No data received")
                raise error

            recv_header = packet.unpack(recv_data, user_metadata)

        except error:
            print("[-] Timeout")
            exception("Failed to send/recv headers")
            raise

        except KeyboardInterrupt:
            print("CTRL_C")
            raise

        except ValueError:
            print("[-] Value Error")

        if recv_header is None:
            print("[-] Received nothing")
        return recv_header

    @classmethod
    def read_file(cls, filename):
        """Reads data from a specified file. Returns number of bytes read."""
        try:
            with open(filename, 'rb') as file:
                bytes_read = file.read(1016)

        except OSError as e_err:
            print("OS Error: ", e_err)
            exception("File not found")
            return -1

        return bytes_read

    @classmethod
    def write_file(cls, filename, data):
        """Writes data to a specified file. Creates non-existant file."""
        try:
            with open(filename, 'wb') as file:
                file.write(data)

        except OSError as e_err:
            print("OS Error: ", e_err)
            exception("File cannot be created/written")
            return False

        return True

    @classmethod
    def resolve_path(cls, filename):
        """Resolves given path to real path."""

        try:
            cwd = getcwd()
            chdir(cwd + '/../../' + DEFAULT_DIR)
            cwd = getcwd()

            Events.safe_path = cwd

            filepath = cwd + '/' + filename

            realpath = path.realpath(filepath)

        except BaseException as e_err:
            print("[-] General error: ", e_err)
            raise SystemExit from e_err

        return realpath

    @classmethod
    def validate(cls, arg, num_args, flag):
        """Validates number of arguments of a specific cmd."""
        data = tuple(map(str, arg.split()))

        valid_data = True

        for _ in data:  # If there is anything in data.
            if not _:
                break
            if len(_) > 2036:
                print("Data is too large [max 2036]")
                return None

        if flag is True:
            if len(data) != num_args and num_args == 3:
                print("Need [username] [password] [R/RW/ADMIN]")
                valid_data = False
            if len(data) > 1 and num_args == 0:
                print('Need [optional path] or nothing')
                valid_data = False

            if valid_data is False:
                return None

        elif len(data) != num_args and num_args == 0:
            print('No options required')
            valid_data = False

        elif len(data) != num_args and num_args == 1:
            print('Need [Option]')
            valid_data = False

        elif len(data) != num_args and num_args == 2:
            print('Need [src] [dst]')
            valid_data = False

        elif len(data) != num_args and num_args == 3:
            print('Need [src] [dst] [Overwrite: Y/N]')
            valid_data = False

        if valid_data is False:
            return None

        return data

    @classmethod
    def check_creds(cls, user, password, delete):
        """Validates credentials."""

        flag = False

        if delete is True:
            if (isinstance(user, str) and len(user[0]) > MAX_USER_LEN):
                print("Username Max: 20 characters")
                return False
            if (isinstance(user, str) and not user):
                print("Username must not be empty")
                return False

            return True

        if (isinstance(user, str) and isinstance(password, str)):
            flag = True

        if (not user or not password) and flag is False:
            print("Username and password must not be empty")
            return False
        if (len(user) > 1 or len(password) > 1) and flag is False:
            print("Username and password must be a singular string each")
            return False
        if len(user[0]) > MAX_USER_LEN or len(password[0]) > MAX_PASS_LEN:
            print("Username Max: 20 characters. Password Max: 30 characters")
            return False

        return True

    @classmethod
    def dir_trans_check(cls, filepath):
        """Checks for directory transversal attack/valid directory."""
        check = path.commonprefix([filepath, Events.safe_path])
        if check != Events.safe_path:
            return False

        return True

    @classmethod
    def delete_file(cls, filepath):
        """Deletes a specified local file."""
        try:
            remove(filepath)
        except FileNotFoundError:
            print("Cannot remove nonexistant file")
            exception("remove file")
            return

        except OSError as e_err:
            print("remove error: ", e_err)
            return

    @classmethod
    def list_dir(cls, filepath):
        """List a specified local directory."""
        try:
            dir_data = listdir(filepath)
        except FileNotFoundError:
            print("Cannot list nonexistant dir")
            exception("listdir")
            return None

        except OSError as e_err:
            print("List dir error: ", e_err)
            return None

        return dir_data

    @classmethod
    def create_dir(cls, dirpath):
        """Creates a specified local directory"""
        try:
            mkdir(dirpath)
        except FileExistsError:
            print("Dir exists already ")
            exception("mkdir")
            return

        except OSError as e_err:
            print("Mkdir error: ", e_err)
            return
