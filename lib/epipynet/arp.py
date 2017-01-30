import binascii
import socket
import struct


ETHERNET_ADDR_BROADCAST = b'\xFF\xFF\xFF\xFF\xFF\xFF'
ETHERNET_ADDR_ZERO = b'\x00\x00\x00\x00\x00\x00'
ETHERTYPE_ARP = 0x0806

IPV4_ADDR_ZERO = b'\x00\x00\x00\x00'

ARP_HARDWARE_ETHERNET = 1
ARP_PROTOCOL_IPV4 = 0x0800

ARP_OPERATION_REQUEST = 1
ARP_OPERATION_REPLY = 2


class ArpPacket(object):

    '''A structured representation of an Address Resolution Protocol packet'''

    def __init__(self) -> None:
        self.destination = ETHERNET_ADDR_ZERO  # type: bytes
        self.source = ETHERNET_ADDR_ZERO  # type: bytes

        self.hardware_type = ARP_HARDWARE_ETHERNET  # type: int
        self.protocol_type = ARP_PROTOCOL_IPV4  # type: int
        self.hardware_addr_len = 6  # type: int
        self.protocol_addr_len = 4  # type: int
        self.operation = 0  # type: int

        self.sender_hardware_addr = ETHERNET_ADDR_ZERO  # type: bytes
        self.sender_protocol_addr = IPV4_ADDR_ZERO  # type: bytes
        self.target_hardware_addr = ETHERNET_ADDR_ZERO  # type: bytes
        self.target_protocol_addr = IPV4_ADDR_ZERO  # type: bytes

    def __repr__(self) -> str:
        r = '<ArpPacket'

        dest_hex = binascii.hexlify(self.destination).decode('ascii')
        r += ' destination=' + dest_hex

        source_hex = binascii.hexlify(self.source).decode('ascii')
        r += ' source=' + source_hex

        r += ' hardware_type=' + repr(self.hardware_type)
        r += ' protocol_type=' + repr(self.protocol_type)
        r += ' hardware_addr_len=' + repr(self.hardware_addr_len)
        r += ' protocol_addr_len=' + repr(self.protocol_addr_len)
        r += ' operation=' + repr(self.operation)

        addr_hex = binascii.hexlify(self.sender_hardware_addr).decode('ascii')
        r += ' sender_hardware_addr=' + addr_hex

        ip_addr = socket.inet_ntoa(self.sender_protocol_addr)
        r += ' sender_protocol_addr=' + ip_addr

        addr_hex = binascii.hexlify(self.target_hardware_addr).decode('ascii')
        r += ' target_hardware_addr=' + addr_hex

        ip_addr = socket.inet_ntoa(self.target_protocol_addr)
        r += ' target_protocol_addr=' + ip_addr

        r += '>'

        return r

    def encode(self) -> bytes:

        'Convert to the bytes suitable for sending over an AF_PACKET socket'

        packet = self.destination + self.source
        packet += struct.pack('!H', ETHERTYPE_ARP)

        packet += struct.pack(
            '!HHBBH',
            self.hardware_type,
            self.protocol_type,
            self.hardware_addr_len,
            self.protocol_addr_len,
            self.operation)

        packet += self.sender_hardware_addr + self.sender_protocol_addr
        packet += self.target_hardware_addr + self.target_protocol_addr

        return packet


def decode(
        packet: bytes) -> ArpPacket:

    'Decode from bytes to an ArpPacket object'

    arp = ArpPacket()

    if len(packet) < 14:
        raise ValueError(packet)

    arp.destination = packet[0:6]
    arp.source = packet[6:12]

    ethertype = struct.unpack('!H', packet[12:14])[0]
    if ethertype != ETHERTYPE_ARP:
        raise ValueError(packet)

    arp_bytes = packet[14:]

    if len(arp_bytes) < 8:
        raise ValueError(packet)

    (arp.hardware_type,
        arp.protocol_type,
        arp.hardware_addr_len,
        arp.protocol_addr_len,
        arp.operation) = struct.unpack('!HHBBH', arp_bytes[0:8])

    expected_arp_len = \
        8 + 2 * arp.hardware_addr_len + 2 * arp.protocol_addr_len
    if len(arp_bytes) < expected_arp_len:
        raise ValueError(packet)

    offset = 8
    arp.sender_hardware_addr = \
        arp_bytes[offset:offset + arp.hardware_addr_len]
    offset += arp.hardware_addr_len

    arp.sender_protocol_addr = \
        arp_bytes[offset:offset + arp.protocol_addr_len]
    offset += arp.protocol_addr_len

    arp.target_hardware_addr = \
        arp_bytes[offset:offset + arp.hardware_addr_len]
    offset += arp.hardware_addr_len

    arp.target_protocol_addr = \
        arp_bytes[offset:offset + arp.protocol_addr_len]
    offset += arp.protocol_addr_len

    return arp
