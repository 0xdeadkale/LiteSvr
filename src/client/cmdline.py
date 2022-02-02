#!/usr/bin/env python3
"""Cmd line module for communicating with the server."""

from logging import exception, basicConfig, DEBUG
from os import path

from action import Events
from packetmetadata import OpCode, RetCode, UserCode, OverwriteCode
from packet import Packet


CLIENT_FILES = 'test/client/'

LOG_FILE = '../Client_Files/debug.out'
basicConfig(filename=LOG_FILE, level=DEBUG)


class ClientCmdline:
    """Command line class to enable communication with the server."""

    # pylint: disable=too-many-instance-attributes
    # pylint: disable=too-many-arguments
    # All needed to work smoothly.

    def __init__(self, ip_addr=None, port=None, user=None, pwd=None, cmd=None):
        self.user = user
        self.pwd = pwd
        self.cmd = cmd
        self.sock = self.generate_sock(ip_addr, port)
        self.login(user, pwd)

        self.s_id = None
        self.opcode = 0
        self.alt_code = 0
        self.response = None

    def generate_sock(self, ip_addr, port):
        """Generates a socket and connects to the server."""
        # pylint: disable=no-self-use

        client_sock = Events.generate_sock(ip_addr, port)

        return client_sock

    def login(self, user, pwd):
        'Login to FTP server: login'
        self.opcode = OpCode.USER.value
        self.alt_code = UserCode.LOGIN.value

        # Validation--------------------------------------
        if self.cmd[0] == 'ls' or self.cmd[0] == 'l_ls':
            num_args = 1
            flag = True
        elif self.cmd[0] == 'get':
            num_args = 2
            flag = False
        elif self.cmd[0] == 'put':
            num_args = 3
            flag = False
        elif self.cmd[0] == 'user_create':
            num_args = 3
            flag = True
        else:
            num_args = 1
            flag = False

        cmd_str = ''
        for _ in self.cmd[1:]:
            cmd_str = cmd_str + " " + _

        data = Events.validate(cmd_str, num_args, flag)
        if data is None:
            return

        creds = []
        creds.append(user)
        creds.append(pwd)

        result = Events.check_creds(creds[0], creds[1], False)
        if result is False:
            return

        # Validation------^^^^^^^^^^^^^^---------------------

        response = self._controller("user", creds, UserCode.LOGIN.value)

        self.response = response

        self._data_handler()

        if response[0] == RetCode.SUCCESS.value:
            self._dispatcher(self.cmd[0], self.cmd[1:])
        else:
            print("Login Failed")
            return

    def user_create(self, arg):
        'Creates a user with specifed permissions: user_create [R/RW/ADMIN]'
        self.opcode = OpCode.USER.value

        result = Events.check_creds(arg[0], arg[1], False)
        if result is False:
            return

        if arg[2] == 'R':
            user_code = UserCode.R_ONLY.value
            self.alt_code = UserCode.R_ONLY.value
        elif arg[2] == 'RW':
            user_code = UserCode.RW_ONLY.value
            self.alt_code = UserCode.RW_ONLY.value
        elif arg[2] == 'ADMIN':
            user_code = UserCode.ADMIN.value
            self.alt_code = UserCode.ADMIN.value
        else:
            print("Invalid [Option]")
            return

        creds = []
        creds.append(arg[0])
        creds.append(arg[1])
        creds.append(self.s_id)

        response = self._controller("user", creds, user_code)

        self.response = response

        self._data_handler()

        return

    def user_delete(self, arg):
        'Deletes a user account (Admin only): user_delete'
        self.opcode = OpCode.USER.value
        self.alt_code = UserCode.DEL.value

        placeholder = ""

        result = Events.check_creds(arg[0], placeholder, True)
        if result is False:
            return

        creds = []
        creds.append(arg[0])
        creds.append(placeholder)
        creds.append(self.s_id)

        response = self._controller("user", creds, UserCode.DEL.value)

        self.response = response

        self._data_handler()

        return

    def remove(self, arg):
        'Deletes file at server: delete [PATH]'

        self.opcode = OpCode.RM.value

        response = self._controller("rm", self.s_id, arg[0])

        self.response = response

        self._data_handler()

    def list(self, arg):
        'Lists remote directory contents: ls [optional path]'

        self.opcode = OpCode.LS.value

        meta_data = []
        meta_data.append(self.s_id)
        if self.response is None:
            meta_data.append(0)
        else:
            meta_data.append(self.response[6])

        response = self._controller("ls", meta_data, arg)

        self.response = response

        decoded = response[7].decode()
        split_me = decoded.split('\x00')[:-1]

        '''Prints out data from server.'''
        file_type = ''
        for entry in split_me:
            file_type = entry[0]
            if file_type == '1':
                print(f'Dir - {entry[1:]}')
            elif file_type == '2':
                print(f'File - {entry[1:]}')

        while self.response[6] != self.response[4]:
            self.list(arg)
            if self.response is None:
                return

        self._data_handler()
        return

    def get(self, arg):
        'Gets file from server and copies to client: get [src] [dst]'
        self.opcode = OpCode.GET.value

        filepath = Events.resolve_path(arg[1])
        valid = Events.dir_trans_check(filepath)
        if valid is True:
            pass
        else:
            print("Delete file operation failed")
            return

        meta_data = []
        meta_data.append(len(arg[0]))
        meta_data.append(self.s_id)

        response = self._controller("get", meta_data, arg[0])

        result = Events.write_file(arg[1], response[3])

        self.response = response

        '''If result fails, correct the response data.'''
        if result is False:
            _ = list(self.response)
            _[0] = RetCode.FAIL.value
            self.response = tuple(_)

        self._data_handler()

    def mkdir(self, arg):
        'Makes directory at server: mkdir [path]'
        self.opcode = OpCode.MKDIR.value

        response = self._controller("mkdir", self.s_id, arg[0])

        self.response = response

        self._data_handler()

    def put(self, arg):
        'Sends file from client to server: put [src] [dst] [Overwrite: Y/N]'
        self.opcode = OpCode.PUT.value

        filepath = Events.resolve_path(arg[0])
        valid = Events.dir_trans_check(filepath)
        if valid is True:
            exists = path.exists(filepath)
            if exists is True:
                pass
            else:
                print("File does not exist")
                return
        else:
            print("dst not valid")
            return

        file_data = Events.read_file(arg[0])
        send_data = arg[1].encode() + file_data

        if arg[2] == 'Y':
            self.alt_code = OverwriteCode.OVERWRITE.value
        elif arg[2] == 'N':
            self.alt_code = OverwriteCode.NO_OVERWRITE.value
        else:
            print("Wrong overwrite flag. Enter 'Y' or 'N'")
            return

        meta_data = []
        meta_data.append(self.alt_code)
        meta_data.append(len(arg[1]))
        meta_data.append(self.s_id)
        meta_data.append(len(file_data))

        response = self._controller("put", meta_data, send_data)

        self.response = response

        self._data_handler()

    def l_delete(self, arg):
        'Deletes file at local: l_delete [PATH]'

        # pylint: disable=no-self-use

        '''Validates path.'''
        filepath = Events.resolve_path(arg[0])
        valid = Events.dir_trans_check(filepath)
        if valid is True:
            exists = path.exists(filepath)
            if exists is True:
                Events.delete_file(filepath)
                print("[SYSTEM] Deleted")
            else:
                print("[SYSTEM] File does not exist")
        else:
            print("[SYSTEM] Delete file out of bounds")

    def l_ls(self, arg):
        'Lists local directory contents: l_ls [optional path]'

        # pylint: disable=no-self-use

        if len(arg) == 0:
            feeder = ''  # root of server
        else:
            feeder = arg[0]

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
            print("[SYSTEM] l_ls path out of bounds")

    def l_mkdir(self, arg):
        'Makes directory at client: l_mkdir [path]'

        # pylint: disable=no-self-use

        dirpath = Events.resolve_path(arg[0])
        valid = Events.dir_trans_check(dirpath)
        if valid is True:
            exists = path.lexists(dirpath)
            if exists is True:
                print("[SYSTEM] Dir already exists")
            else:
                Events.create_dir(dirpath)
                print("[SYSTEM] dir created")
        else:
            print("[SYSTEM] l_mkdir path out of bounds")

    # ----------------------------Helper methods----------------------------- #
    def _dispatcher(self, cmd, *args, **kwargs):

        cmds = {'user_create': self.user_create,
                'user_delete': self.user_delete,
                'rm': self.remove,
                'ls': self.list,
                'get': self.get,
                'mkdir': self.mkdir,
                'put': self.put,
                'l_delete': self.l_delete,
                'l_ls': self.l_ls,
                'l_mkdir': self.l_mkdir}
        try:
            cmds[cmd](*args, **kwargs)
        except KeyError:
            print(f'Command: |{cmd}| not recognized')
            exception("Dispatcher Key error")
            raise

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
            raise

        response = Events.user_activity(self.sock, data)

        return response

    def _data_handler(self):
        print("---Server Status---")

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
            print("[-] Session timed out/error")
        else:
            print('*'*12)

        self.opcode = 0
        self.alt_code = 0
        self.response = None

        print("-"*12)
