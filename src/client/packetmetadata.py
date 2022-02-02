#!/usr/bin/env python3
"""Dataclasses that contain packet-specific information."""

from struct import calcsize
from dataclasses import dataclass
from enum import Enum


@dataclass
class UserRequest:
    """User request dataclass"""

    # pylint: disable=too-many-instance-attributes
    # All attributes are needed to parse packet correctly.

    opcode: int = 0
    flag: int = 0
    rsvd: int = 0
    u_len: int = 0
    p_len: int = 0
    s_id: int = 0
    data: str = None

    items = 7
    total_data_len: int = 0
    fmt: str = None
    fmt_size: int = 0

    def calc_s(self):
        self.total_data_len: int = self.u_len + self.p_len
        self.fmt: str = f'!BBHHHI{str(self.total_data_len)}s'
        self.fmt_size: int = calcsize(self.fmt)


@dataclass
class UserReply:
    """User reply dataclass"""

    retcode: int = 0
    rsvd: int = 0
    s_id: int = 0

    items: int = 3
    fmt: str = "!BBI"
    fmt_size: int = calcsize(fmt)


@dataclass
class RmRequest:
    """Remove request dataclass"""

    # pylint: disable=too-many-instance-attributes
    # All attributes are needed to parse packet correctly.

    opcode: int = 0
    rsvd: int = 0
    len: int = 0
    s_id: int = 0
    data: str = None

    items: int = 5
    fmt: str = None
    fmt_size: int = 0

    def calc_s(self):
        self.fmt: str = f'!BBHI{str(self.len)}s'
        self.fmt_size: int = calcsize(self.fmt)


@dataclass
class RmReply:
    """Remove reply dataclass"""
    retcode: int = 0

    items: int = 1
    fmt: str = "!B"
    fmt_size: int = calcsize(fmt)


@dataclass
class LsRequest:
    """LS request dataclass"""

    # pylint: disable=too-many-instance-attributes
    # All attributes are needed to parse packet correctly.

    opcode: int = 0
    rsvd: int = 0
    len: int = 0
    s_id: int = 0
    pos: int = 0
    data: str = None

    items: int = 6
    fmt: str = None
    fmt_size: int = 0

    def calc_s(self):
        self.fmt: str = f'!BBHII{str(self.len)}s'
        self.fmt_size: int = calcsize(self.fmt)


@dataclass
class LsReply:
    """LS reply dataclass"""

    # pylint: disable=too-many-instance-attributes
    # All attributes are needed to parse packet correctly.

    retcode: int = 0
    rsvd1: int = 0
    rsvd2: int = 0
    rsvd3: int = 0
    data_len: int = 0
    msg_len: int = 0
    pos: int = 0
    data: bytearray = None

    items: int = 7
    pre_fmt: str = '!BBBBIII'
    post_fmt: str = None
    fmt_size: int = calcsize(pre_fmt)

    def calc_s(self):
        self.post_fmt: str = f'!BBBBIII{str(self.msg_len)}s'
        self.fmt_size: int = calcsize(self.post_fmt)


@dataclass
class GetRequest:
    """Get request dataclass"""

    # pylint: disable=too-many-instance-attributes
    # All attributes are needed to parse packet correctly.

    opcode: int = 0
    rsvd: int = 0
    len: int = 0
    s_id: int = 0
    data: str = None

    items: int = 5
    fmt: str = None
    fmt_size: int = 0

    def calc_s(self):
        self.fmt: str = f'!BBHI{str(self.len)}s'
        self.fmt_size: int = calcsize(self.fmt)


@dataclass
class GetReply:
    """Get reply dataclass"""

    # pylint: disable=too-many-instance-attributes
    # All attributes are needed to parse packet correctly.

    retcode: int = 0
    rsvd: int = 0
    len: int = 0
    data: bytearray = None

    items: int = 4
    pre_fmt: str = '!BBI'
    post_fmt: str = None
    fmt_size: int = calcsize(pre_fmt)

    def calc_s(self):
        self.post_fmt: str = f'!BBI{str(self.len)}s'
        self.fmt_size: int = calcsize(self.post_fmt)


@dataclass
class MkdirRequest:
    """Make directory request dataclass"""

    # pylint: disable=too-many-instance-attributes
    # All attributes are needed to parse packet correctly.

    opcode: int = 0
    rsvd_8: int = 0
    len: int = 0
    s_id: int = 0
    rsvd_32: int = 0
    data: str = None

    items: int = 6
    fmt: str = None
    fmt_size: int = 0

    def calc_s(self):
        self.fmt: str = f'!BBHII{str(self.len)}s'
        self.fmt_size: int = calcsize(self.fmt)


@dataclass
class MkdirReply:
    """Make directory reply dataclass"""
    retcode: int = 0

    items: int = 1
    fmt: str = "!B"
    fmt_size: int = calcsize(fmt)


@dataclass
class PutRequest:
    """Put request dataclass"""

    # pylint: disable=too-many-instance-attributes
    # All attributes are needed to parse packet correctly.

    opcode: int = 0
    flag: int = 0
    name_len: int = 0
    s_id: int = 0
    data_len: int = 0
    data: str = None

    items: int = 6
    total_len: int = 0
    fmt: str = None
    fmt_size: int = 0

    def calc_s(self):
        self.total_len: int = self.name_len + self.data_len
        self.fmt: str = f'!BBHII{str(self.total_len)}s'
        self.fmt_size: int = calcsize(self.fmt)


@dataclass
class PutReply:
    """Put reply dataclass"""
    retcode: int = 0

    items: int = 1
    fmt: str = "!B"
    fmt_size: int = calcsize(fmt)


class OpCode(Enum):
    """Enum for Operation codes"""
    USER = 1
    RM = 2
    LS = 3
    GET = 4
    MKDIR = 5
    PUT = 6


class RetCode(Enum):
    """Enum for Return codes"""
    SUCCESS = 1
    S_ERR = 2
    P_ERR = 3
    U_EXIST = 4
    F_EXIST = 5
    FAIL = 255


class UserCode(Enum):
    """Enum for User codes"""
    LOGIN = 0
    R_ONLY = 1
    RW_ONLY = 2
    ADMIN = 3
    DEL = 255


class OverwriteCode(Enum):
    """Enum for PUT Overwrite codes"""
    NO_OVERWRITE = 0
    OVERWRITE = 1
