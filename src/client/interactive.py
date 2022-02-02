#!/usr/bin/env python3
"""Interactive module for communicating with the server."""

from cmd import Cmd
from os import path
from logging import exception, basicConfig, DEBUG
from urllib import response


from action import Events
from packetmetadata import OpCode, RetCode, UserCode, OverwriteCode
from packet import Packet

LOG_FILE = '../Client_Files/debug.out'
basicConfig(filename=LOG_FILE, level=DEBUG)


class ClientInteractive(Cmd):
    """Interactive class to enable communication with the server."""

    # pylint: disable=too-many-instance-attributes
    # All needed to work smoothly.

    def __init__(self, ip_addr=None, port=None):
        Cmd.__init__(self)
        self.ip_addr = ip_addr
        self.port = port

    intro = 'Capstone Client. Type help or ? to list commands.\n'
    prompt = '(Guest)> '
    sock = None
    s_id = 0
    opcode = 0
    alt_code = 0
    response = None

    def preloop(self):
        print("---Enter IP and Port to connect to---")

        '''Validate ip and port.'''
        while True:
            ip_addr_str = ""
            port_int = 0

            try:
                ip_addr_str = str(self.ip_addr)
                port_int = int(self.port)
            except (ValueError, TypeError):
                print("IP must be a string, Port must be an integer")
                break
            except BaseException as e_err:
                print(f'{e_err}\nTry again...')
                raise e_err from SystemExit
            else:
                break

        self.sock = Events.generate_sock(ip_addr_str, port_int)

    def postcmd(self, stop: bool, line: str) -> bool:
        self._data_handler()
        return super().postcmd(stop, line)

    # --------------Client cmds-------------- #
    def do_login(self, arg):
        """Login to FTP server: login"""

        self.opcode = OpCode.USER.value
        self.alt_code = UserCode.LOGIN.value

        data = Events.validate(arg, 0, False)
        if data is None:
            return

        creds = []
        creds.append(input('Username: '))
        creds.append(input('Password: '))

        if creds[0] == "" or creds[1] == "":
            print("Empty creds is not valid")
            return

        username = creds[0].split()
        password = creds[1].split()

        result = Events.check_creds(username, password, False)
        if result is False:
            return

        response = self._controller("user", creds, UserCode.LOGIN.value)

        self.response = response

        if response[0] == RetCode.SUCCESS.value:
            self.prompt = f'({creds[0]})> '

        return

    def do_user_create(self, arg):
        """Creates user with specifed permissions: user_create [R/RW/ADMIN]"""
        self.opcode = OpCode.USER.value

        data = Events.validate(arg, 1, False)
        if data is None:
            print("[option: R/RW/ADMIN]")
            return

        if arg == 'R':
            user_code = UserCode.R_ONLY.value
            self.alt_code = UserCode.R_ONLY.value
        elif arg == 'RW':
            user_code = UserCode.RW_ONLY.value
            self.alt_code = UserCode.RW_ONLY.value
        elif arg == 'ADMIN':
            user_code = UserCode.ADMIN.value
            self.alt_code = UserCode.ADMIN.value
        else:
            print("Invalid [Option]")
            return

        creds = []
        creds.append(input('Username: '))
        creds.append(input('Password: '))
        creds.append(self.s_id)

        username = creds[0].split()
        password = creds[1].split()

        result = Events.check_creds(username, password, False)
        if result is False:
            return

        response = self._controller("user", creds, user_code)

        self.response = response

        return

    def do_user_delete(self, arg):
        """Deletes a user account (Admin only): user_delete"""

        self.opcode = OpCode.USER.value
        self.alt_code = UserCode.DEL.value

        data = Events.validate(arg, 0, False)
        if data is None:
            return

        placeholder = ""

        creds = []
        creds.append(input('Username: '))
        creds.append(placeholder)
        creds.append(self.s_id)

        username = creds[0].split()

        result = Events.check_creds(username, None, True)
        if result is False:
            return

        response = self._controller("user", creds, UserCode.DEL.value)

        self.response = response

        return

    def do_rm(self, arg):
        """Deletes file at server: delete [PATH]"""
        self.opcode = OpCode.RM.value

        data = Events.validate(arg, 1, False)
        if data is None:
            return

        response = self._controller("rm", self.s_id, data[0])

        self.response = response

        return

    def do_ls(self, arg):
        """Lists remote directory contents: ls [optional path]"""
        self.opcode = OpCode.LS.value

        data = Events.validate(arg, 0, True)
        if data is None:
            return

        meta_data = []
        meta_data.append(self.s_id)
        if self.response is None:
            meta_data.append(0)
        else:
            meta_data.append(self.response[6])

        response = self._controller("ls", meta_data, data)

        self.response = response

        decoded = response[7].decode()
        split_me = decoded.split('\x00')[:-1]

        '''Prints dir data recieved from server.'''
        file_type = ''
        for entry in split_me:
            file_type = entry[0]
            if file_type == '1':
                print(f'Dir - {entry[1:]}')
            elif file_type == '2':
                print(f'File - {entry[1:]}')

        while self.response[6] != self.response[4]:
            self.do_ls(arg)

        return

    def do_get(self, arg):
        """Gets file from server and copies to client: get [src] [dst]"""
        self.opcode = OpCode.GET.value

        data = Events.validate(arg, 2, False)
        if data is None:
            return

        filepath = Events.resolve_path(data[1])
        valid = Events.dir_trans_check(filepath)
        if valid is True:
            pass
        else:
            print("Client directory not valid")
            return

        meta_data = []
        meta_data.append(len(data[0]))
        meta_data.append(self.s_id)

        response = self._controller("get", meta_data, data[0])

        print(data)
        print(response)
        result = Events.write_file(data[1], response[3])

        self.response = response

        '''Response correction if write fails.'''
        if result is False:
            _ = list(self.response)
            _[0] = RetCode.FAIL.value
            self.response = tuple(_)

    def do_mkdir(self, arg):
        """Makes directory at server: mkdir [path]"""
        self.opcode = OpCode.MKDIR.value

        data = Events.validate(arg, 1, False)
        if data is None:
            return

        response = self._controller("mkdir", self.s_id, data[0])

        self.response = response

        return

    def do_put(self, arg):
        """Sends file from client to be placed in server: put [src] [dst]"""
        self.opcode = OpCode.PUT.value

        data = Events.validate(arg, 2, False)
        if data is None:
            return

        '''Validates file path.'''
        filepath = Events.resolve_path(data[0])
        valid = Events.dir_trans_check(filepath)
        if valid is True:
            exists = path.exists(filepath)
            if exists is True:
                pass
            else:
                print("File does not exist")
        else:
            print("dst not valid")

        file_data = Events.read_file(data[0])

        '''Response correction if file_data fails.'''
        if file_data == -1:
            _ = list(self.response)
            _[0] = RetCode.FAIL.value
            self.response = tuple(_)
            return

        send_data = data[1].encode() + file_data

        '''Retrieve overwrite flag choice.'''
        try:
            while True:
                flag = str(input('Overwrite file? (y/n)> '))
                print(flag)
                if flag == "y" or flag == "n":
                    break

                print('Enter y or n')
                continue
        except KeyboardInterrupt:
            return

        if flag == 'y':
            self.alt_code = OverwriteCode.OVERWRITE.value
        else:
            self.alt_code = OverwriteCode.NO_OVERWRITE.value

        meta_data = []
        meta_data.append(self.alt_code)
        meta_data.append(len(data[1]))
        meta_data.append(self.s_id)
        meta_data.append(len(file_data))

        response = self._controller("put", meta_data, send_data)

        self.response = response

        return

    def do_l_delete(self, arg):
        """Deletes file at local: l_delete [PATH]"""

        # pylint: disable=no-self-use

        data = Events.validate(arg, 1, False)
        if data is None:
            return

        filepath = Events.resolve_path(data[0])
        valid = Events.dir_trans_check(filepath)
        if valid is True:
            exists = path.exists(filepath)
            if exists is True:
                Events.delete_file(filepath)
                print("[SYSTEM] Deleted")
            else:
                print("[SYSTEM] File does not exist")
        else:
            print("[SYSTEM] Delete: out of root dir")

    def do_l_ls(self, arg):
        """Lists local directory contents: l_ls [optional path]"""

        # pylint: disable=no-self-use

        data = Events.validate(arg, 1, True)
        if len(data) == 0:
            feeder = ''  # root of server
        else:
            feeder = data[0]

        '''Validates directory path.'''
        filepath = Events.resolve_path(feeder)
        valid = Events.dir_trans_check(filepath)
        if valid is True:
            ls_data = Events.list_dir(filepath)
            if ls_data is None:
                return

            print("---[SYSTEM]---")
            for entry in ls_data:
                print(entry)
            print("---[SYSTEM]---")

        else:
            print("[SYSTEM] l_ls: out of root dir")

    def do_l_mkdir(self, arg):
        """Makes directory at client: l_mkdir [path]"""

        # pylint: disable=no-self-use

        data = Events.validate(arg, 1, False)
        if data is None:
            return

        '''Validates directory path.'''
        dirpath = Events.resolve_path(data[0])
        valid = Events.dir_trans_check(dirpath)
        if valid is True:
            exists = path.lexists(dirpath)
            if exists is True:
                print("[SYSTEM] Dir already exists")
            else:
                Events.create_dir(dirpath)
                print("[SYSTEM] dir created")
        else:
            print("[SYSTEM] l_mkdir: out of root dir")

    def do_quit(self, arg):
        """Quit client"""
        data = Events.validate(arg, 0, False)
        if data is None:
            return None

        self.response = None
        print('Exiting...')
        return True

    def do_exit(self, arg):
        """Exit client"""
        data = Events.validate(arg, 0, False)
        if data is None:
            return None

        self.response = None
        print('Exiting...')
        return True

    # -----------------------------Helper methods---------------------------- #
    def _controller(self, cmd, *args, **kwargs):
        packet = Packet()

        cmds = {'user': packet.user_request,
                'rm': packet.rm_request,
                'ls': packet.ls_request,
                'get': packet.get_request,
                'mkdir': packet.mkdir_request,
                'put': packet.put_request}

        try:
            data = cmds[cmd](*args, **kwargs)

        except KeyError:
            print(f'Command: |{cmd}| not recognized')
            exception("Controller Key error")
            return None

        response = Events.user_activity(self.sock, data)

        return response

    def _data_handler(self):
        print("---Server Status---")

        try:
            if self.response is None:
                print('*'*12)
            elif self.opcode == OpCode.USER.value and \
                    self.alt_code == UserCode.LOGIN.value:

                if self.response[0] == RetCode.SUCCESS.value:
                    print("[+] Login Success")
                    self.s_id = self.response[2]
                elif self.response[0] == RetCode.FAIL.value:
                    print("[-] Login failed")
            elif self.response[0] == RetCode.SUCCESS.value:
                print("[+] Success")
            elif self.response[0] == RetCode.FAIL.value:
                print("[-] Failed")
            elif self.response[0] == RetCode.P_ERR.value:
                print("[-] Permission Fail")
            elif self.response[0] == RetCode.F_EXIST.value:
                print("[-] No overwrite - File exists")
            elif self.response[0] == RetCode.U_EXIST.value:
                print("[-] User already exists")

            elif self.response[0] == RetCode.S_ERR.value:
                self.s_id = 0
                self.prompt = '(Guest)> '
                print("[-] Session timed out/error")
            else:
                print("*******")

        except (ValueError, IndexError):
            print("[-] Error. Restarting...")

        self.opcode = 0
        self.alt_code = 0
        self.response = None

        print("-"*12)
