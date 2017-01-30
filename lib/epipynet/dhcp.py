import binascii
import socket
import struct

from typing import *


DHCP_OPERATION_BOOTREQUEST = 1
DHCP_OPERATION_BOOTREPLY = 2

DHCP_HARDWARE_ETHERNET = 1

DHCP_FLAG_BROADCAST = 0x8000

DHCP_OPTIONS_MAGIC = 0x63825363

DHCP_OPTION_SUBNET = 1
DHCP_OPTION_ROUTER = 3
DHCP_OPTION_DNS = 6
DHCP_OPTION_IP_REQUEST = 50
DHCP_OPTION_TYPE = 53
DHCP_OPTION_SERVER = 54
DHCP_OPTION_PARAM_REQUEST = 55

DHCP_TYPE_DISCOVER = struct.pack('B', 1)
DHCP_TYPE_OFFER = struct.pack('B', 2)
DHCP_TYPE_REQUEST = struct.pack('B', 3)
DHCP_TYPE_DECLINE = struct.pack('B', 4)
DHCP_TYPE_ACK = struct.pack('B', 5)
DHCP_TYPE_NAK = struct.pack('B', 6)
DHCP_TYPE_RELEASE = struct.pack('B', 7)


ETHERNET_ADDR_ZERO = b'\x00\x00\x00\x00\x00\x00'
IPV4_ADDR_ZERO = b'\x00\x00\x00\x00'


DhcpOption = Tuple[int, bytes]


class DhcpPacket(object):

    'A Dynamic Host Configuration Protocol packet'

    def __init__(self) -> None:
        self.operation = 0  # type: int
        self.hardware_type = DHCP_HARDWARE_ETHERNET  # type: int
        self.hardware_length = 6  # type: int
        self.hops = 0  # type: int
        self.xid = 0  # type: int
        self.seconds = 0  # type: int
        self.flags = 0  # type: int

        self.client_addr = IPV4_ADDR_ZERO  # type: bytes
        self.your_addr = IPV4_ADDR_ZERO  # type: bytes
        self.server_addr = IPV4_ADDR_ZERO  # type: bytes
        self.relay_addr = IPV4_ADDR_ZERO  # type: bytes
        self.client_hardware_addr = ETHERNET_ADDR_ZERO  # type: bytes

        self.server_name = ''  # type: str
        self.filename = ''  # type: str

        self.options = []  # type: List[DhcpOption]

    def __repr__(self) -> str:
        r = '<DhcpPacket'

        r += ' operation=' + repr(self.operation)
        r += ' hardware_type=' + repr(self.hardware_type)
        r += ' hardware_length=' + repr(self.hardware_length)
        r += ' hops=' + repr(self.hops)

        r += ' xid=%08X' % self.xid

        r += ' seconds=' + repr(self.seconds)
        r += ' flags=%04X' % self.flags

        ciaddr = socket.inet_ntoa(self.client_addr)
        r += ' client_addr=' + ciaddr

        yiaddr = socket.inet_ntoa(self.your_addr)
        r += ' your_addr=' + yiaddr

        siaddr = socket.inet_ntoa(self.server_addr)
        r += ' server_addr=' + siaddr

        giaddr = socket.inet_ntoa(self.relay_addr)
        r += ' relay_addr=' + giaddr

        chaddr_hex = \
            binascii.hexlify(self.client_hardware_addr).decode('ascii')
        r += ' client_hardware_addr=' + chaddr_hex

        r += ' server_name=' + repr(self.server_name)
        r += ' filename=' + repr(self.filename)

        r += ' options=' + repr(self.options)

        r += '>'
        return r

    def encode(self) -> bytes:

        'Encode the packet into bytes'

        packet = struct.pack(
            '!BBBBIHH',
            self.operation,
            self.hardware_type,
            self.hardware_length,
            self.hops,
            self.xid,
            self.seconds,
            self.flags)

        if len(self.client_addr) != 4 or \
                len(self.your_addr) != 4 or \
                len(self.server_addr) != 4 or \
                len(self.relay_addr) != 4:
            raise ValueError(self)

        packet += self.client_addr
        packet += self.your_addr
        packet += self.server_addr
        packet += self.relay_addr

        packet += struct.pack('16s', self.client_hardware_addr)
        packet += struct.pack('64s', self.server_name.encode())
        packet += struct.pack('128s', self.filename.encode())

        packet += struct.pack('!I', DHCP_OPTIONS_MAGIC)
        for option in self.options:
            packet += struct.pack('BB', option[0], len(option[1]))
            packet += option[1]

        return packet

    def get_option(
            self,
            code: int) -> bytes:

        'Get the option with a particular code value, or raise KeyError'

        for option in self.options:
            if option[0] == code:
                return option[1]

        raise KeyError(code)


def decode_options(
        option_bytes: bytes) -> List[DhcpOption]:

    'Decode the options into a list of tuples in (code, bytes) format'

    if len(option_bytes) == 0:
        return []

    if len(option_bytes) < 4:
        raise ValueError(option_bytes)

    if struct.unpack('!I', option_bytes[0:4])[0] != DHCP_OPTIONS_MAGIC:
        raise ValueError(option_bytes)

    options = []  # type: List[DhcpOption]
    remaining = option_bytes[4:]  # type: bytes
    while len(remaining) > 0:
        code = remaining[0]

        if code == 0:
            remaining = remaining[1:]
            continue

        if code == 255:
            return options

        if len(remaining) < 2:
            raise ValueError(option_bytes)

        length = remaining[1]
        if len(remaining) < 2 + length:
            raise ValueError(option_bytes)

        option = (code, remaining[2:2 + length])
        options.append(option)
        remaining = remaining[2 + length:]

    return options


def decode(
        packet: bytes) -> DhcpPacket:

    'Decode the bytes for an incoming packet into a DhcpPacket object'

    dhcp = DhcpPacket()
    expected_size = 236

    if len(packet) < expected_size:
        raise ValueError(packet)

    (dhcp.operation,
        dhcp.hardware_type,
        dhcp.hardware_length,
        dhcp.hops,
        dhcp.xid,
        dhcp.seconds,
        dhcp.flags) = struct.unpack('!BBBBIHH', packet[0:12])

    dhcp.client_addr = packet[12:16]
    dhcp.your_addr = packet[16:20]
    dhcp.server_addr = packet[20:24]
    dhcp.relay_addr = packet[24:28]

    dhcp.client_hardware_addr = packet[28:34]
    dhcp.server_name = packet[44:108].split(b'\0')[0].decode()
    dhcp.filename = packet[108:236].split(b'\0')[0].decode()

    option_bytes = packet[236:]
    dhcp.options = decode_options(option_bytes)

    return dhcp
