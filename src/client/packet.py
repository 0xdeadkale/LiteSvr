#!/usr/bin/env python3
"""Packet module that popoulates each type of packet with received data."""

from dataclasses import asdict
from struct import pack, unpack

from packetmetadata import UserRequest, RmRequest, LsRequest, GetRequest, \
    MkdirRequest, PutRequest, GetReply, LsReply, OpCode, UserCode


class Packet:
    """Packet class that contains all different request packets."""

    def user_request(self, creds, flag):
        """Populates user request packet."""
        packet = UserRequest()

        # ----------Login User--------- #
        if flag == UserCode.LOGIN.value:

            packet.opcode = OpCode.USER.value
            packet.flag = UserCode.LOGIN.value
            packet.rsvd = 0
            packet.u_len = len(creds[0])
            packet.p_len = len(creds[1])
            packet.s_id = 0
            packet.data = f'{creds[0]}{creds[1]}'.encode()

        # ----------Delete User--------- #
        elif flag == UserCode.DEL.value:
            packet.opcode = OpCode.USER.value
            packet.flag = UserCode.DEL.value
            packet.rsvd = 0
            packet.u_len = len(creds[0])
            packet.p_len = len(creds[1])
            packet.s_id = creds[2]
            packet.data = f'{creds[0]}{creds[1]}'.encode()

        # ----------Create User---------- #
        else:
            packet.opcode = OpCode.USER.value
            packet.flag = flag  # R/RW/ADMIN
            packet.rsvd = 0
            packet.u_len = len(creds[0])
            packet.p_len = len(creds[1])
            packet.s_id = creds[2]
            packet.data = f'{creds[0]}{creds[1]}'.encode()

        packet.calc_s()

        return self.pack(packet)

    def rm_request(self, s_id, data):
        """Populates remove request packet."""
        packet = RmRequest()

        packet.opcode = OpCode.RM.value
        packet.rsvd = 0
        packet.len = len(data)
        packet.s_id = s_id
        packet.data = f'{data}'.encode()

        packet.calc_s()

        return self.pack(packet)

    def ls_request(self, meta_data, data):
        """Populates ls request packet."""
        packet = LsRequest()

        if len(data) == 0:
            data = ''  # root of server
            packet.data = data.encode()
        else:
            packet.data = f'{data[0]}'.encode()

        packet.opcode = OpCode.LS.value
        packet.rsvd = 0
        packet.len = len(packet.data)
        packet.s_id = meta_data[0]
        packet.pos = meta_data[1]

        packet.calc_s()

        return self.pack(packet)

    def get_request(self, meta_data, data):
        """Populates get request packet."""
        packet = GetRequest()

        packet.opcode = OpCode.GET.value
        packet.rsvd = 0
        packet.len = meta_data[0]
        packet.s_id = meta_data[1]
        packet.data = f'{data}'.encode()

        packet.calc_s()

        return self.pack(packet)

    def mkdir_request(self, s_id, data):
        """Populates mkdir request packet."""
        packet = MkdirRequest()

        packet.opcode = OpCode.MKDIR.value
        packet.rsvd_8 = 0
        packet.len = len(data)
        packet.s_id = s_id
        packet.rsvd_32 = 0
        packet.data = f'{data}'.encode()

        packet.calc_s()

        return self.pack(packet)

    def put_request(self, meta_data, data):
        """Populates put request packet."""
        packet = PutRequest()

        packet.opcode = OpCode.PUT.value
        packet.flag = meta_data[0]  # Overwrite/No overwrite.
        packet.name_len = meta_data[1]
        packet.s_id = meta_data[2]
        packet.data_len = meta_data[3]
        packet.data = data

        packet.calc_s()

        return self.pack(packet)

    @classmethod
    def pack(cls, packet):
        """Packs packet data to be sent to the server."""

        try:
            data = pack(
                packet.fmt, *(list(asdict(packet).values()))[:packet.items])
        except ValueError:
            print("Cannot pack data")
            raise

        return data

    @classmethod
    def unpack(cls, data, packet_type):
        """Unpacks data received from the server to be used in the client."""
        packet = packet_type

        try:
            if isinstance(packet, GetReply):
                _ = unpack(packet.pre_fmt, data[: packet.fmt_size])
                packet.retcode, packet.rsvd, packet.len = _

                packet.calc_s()
                reply = unpack(packet.post_fmt, data[: packet.fmt_size])
            elif isinstance(packet, LsReply):
                _ = unpack(packet.pre_fmt, data[: packet.fmt_size])
                packet.retcode, packet.rsvd1, packet.rsvd2, packet.rsvd3, \
                    packet.data_len, packet.msg_len, packet.pos = _

                packet.calc_s()
                reply = unpack(packet.post_fmt, data[: packet.fmt_size])
            else:
                reply = unpack(packet.fmt, data[: packet.fmt_size])

        except ValueError:
            print("Cannot unpack data")
            raise

        return reply
