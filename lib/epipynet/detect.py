import asyncio
import contextlib
import os
import struct
import socket
import syslog

from typing import *

import epipynet.arp
import epipynet.dhcp
import epipynet.netconfig


ARP_PACKET_TIME = 0.01
ARP_BATCH_TIME = 1

ARP_TIMEOUT = 1
ARP_RETRIES = 3

DHCP_TIMEOUT = 1
DHCP_RETRIES = 10

SO_BINDTODEVICE = 25

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68

TEST_ARP_PORT = 4044
TEST_DHCP_PORT = 4045
TestMode = 'EPIPYNET_TEST' in os.environ

if TestMode:
    DHCP_SEND_ADDRESS = ('localhost', TEST_DHCP_PORT)
else:
    DHCP_SEND_ADDRESS = ('255.255.255.255', DHCP_SERVER_PORT)


#  (ip_address, netmask, gateway)
NetworkConfigGenerator = \
    Generator[Any, None, epipynet.netconfig.NetworkConfig]
DhcpPacketGenerator = \
    Generator[Any, None, epipynet.dhcp.DhcpPacket]


#  This nonsense is because Python 3.4.2 lacks ensure_future,
#  but has async, however, mypy 0.470 understands ensure_future,
#  but not async.
try:
    ensure_future = asyncio.ensure_future
except AttributeError:
    ensure_future = getattr(asyncio, 'async')


class NoAvailableIPAddressException(Exception):

    '''Raised when we have found a gateway, but no unused IP addresses
    exist on the subnet'''

    pass


def enumerate_subnet_addresses(
        network: epipynet.netconfig.NetworkConfig) \
        -> Generator[str, None, None]:

    '''Given a gateway and netmask, generate all valid IP addresses
    on the subnet.'''

    netmask_int = struct.unpack('!I', socket.inet_aton(network.netmask))[0]
    gateway_int = struct.unpack('!I', socket.inet_aton(network.gateway))[0]

    for i in range(1, (1 << 32) - netmask_int):
        new_ip = (gateway_int & netmask_int) + i
        yield socket.inet_ntoa(struct.pack('!I', new_ip))


def get_test_socket(
        port: int) -> socket.socket:

    'Get a UDP socket simulating an ethernet packet socket for testing'

    sock = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    addr = ('localhost', port)
    sock.connect(addr)

    return sock


def get_dhcp_socket(
        interface_name: str) -> socket.socket:

    '''Open a socket for doing UDP.

    We need an explicit interface association since the interface likely
    does not have an IP address already configured.'''

    if TestMode:
        return get_test_socket(TEST_DHCP_PORT)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    sock.bind(('0.0.0.0', DHCP_CLIENT_PORT))
    interface_name_bytes = interface_name.encode('ascii')
    sock.setsockopt(
        socket.SOL_SOCKET, SO_BINDTODEVICE, interface_name_bytes)

    return sock


def get_ethertype_socket(
        interface_name: str,
        ethertype: int) -> socket.socket:

    'Get an ethernet packet socket bound to a particular ethertype'

    if TestMode:
        return get_test_socket(TEST_ARP_PORT)

    sock = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethertype))

    sock.bind((interface_name, ethertype))
    return sock


def get_mac_address(
        arp_socket: socket.socket) -> bytes:

    'Return the hardware address ("MAC address") of an AF_PACKET socket'

    if TestMode:
        local_mac_address = epipynet.arp.ETHERNET_ADDR_ZERO
    else:
        local_mac_address = arp_socket.getsockname()[4]

    return local_mac_address


def send_arp_request(
        arp_socket: socket.socket,
        ip_address: bytes) -> None:

    'Send an ARP packet requesting the hardware address for an IP'

    mac_address = get_mac_address(arp_socket)

    arp = epipynet.arp.ArpPacket()
    arp.destination = epipynet.arp.ETHERNET_ADDR_BROADCAST
    arp.source = mac_address
    arp.operation = epipynet.arp.ARP_OPERATION_REQUEST
    arp.sender_hardware_addr = mac_address
    arp.target_protocol_addr = ip_address

    arp_packet = arp.encode()
    arp_socket.send(arp_packet)


IpFutureTuple = Tuple[asyncio.Future, Any]


class ArpReplyListener(object):

    'Listen for ARP replies, and complete futures expected replies arrive'

    def __init__(
            self,
            event_loop: asyncio.AbstractEventLoop,
            listen_socket: socket.socket) -> None:

        self.ip_futures = {}  # type: Dict[bytes, IpFutureTuple]
        self.event_loop = event_loop  # type: asyncio.AbstractEventLoop
        self.socket = listen_socket  # type: socket.socket

    def start(self) -> None:

        'Start listening to our socket'

        self.event_loop.add_reader(self.socket.fileno(), self.on_recv)

    def stop(self) -> None:

        'Stop listening for replies'

        self.event_loop.remove_reader(self.socket.fileno())

    def listen_for_ip(
            self,
            ip_address: bytes,
            ip_future: asyncio.Future,
            ip_future_value) -> None:

        'If an ARP reply for the given IP arrives, complete the given future'

        self.ip_futures[ip_address] = (ip_future, ip_future_value)

    def on_recv(self) -> None:

        'We got an ARP packet.  Receive it, potentially completing a future'

        packet = self.socket.recv(4096)

        try:
            reply = epipynet.arp.decode(packet)
        except ValueError:
            return

        if reply.operation == epipynet.arp.ARP_OPERATION_REPLY:
            ip_addr = reply.sender_protocol_addr

            try:
                (future, future_value) = self.ip_futures[ip_addr]
            except KeyError:
                return

            if not future.done():
                future.set_result(future_value)

            del self.ip_futures[ip_addr]


@asyncio.coroutine
def exchange_dhcp(
        event_loop: asyncio.AbstractEventLoop,
        dhcp_socket: socket.socket,
        out_packet: epipynet.dhcp.DhcpPacket,
        reply_type: bytes,
        ignore_ip: bytes) -> DhcpPacketGenerator:

    '''Send a DHCP message and listen for a matching reply.

    Check the XID of the reply to ensure it matches our request.
    Retransmit a few times if no reply is available.'''

    for i in range(DHCP_RETRIES):
        dhcp_socket.sendto(out_packet.encode(), DHCP_SEND_ADDRESS)

        recv_future = asyncio.Future()  # type: asyncio.Future

        def on_recv():
            recv_bytes = dhcp_socket.recv(4096)
            try:
                reply = epipynet.dhcp.decode(recv_bytes)
            except ValueError:
                return

            if reply.xid != out_packet.xid:
                return

            if reply.server_addr == ignore_ip:
                return

            try:
                dhcp_type = reply.get_option(epipynet.dhcp.DHCP_OPTION_TYPE)
            except KeyError:
                return

            if dhcp_type != reply_type:
                return

            if not recv_future.done():
                recv_future.set_result(reply)

        event_loop.add_reader(dhcp_socket.fileno(), on_recv)
        try:
            yield from asyncio.wait([recv_future], timeout=DHCP_TIMEOUT)
        finally:
            event_loop.remove_reader(dhcp_socket.fileno())

        if recv_future.done():
            return recv_future.result()

    return None


def build_dhcp_discover(
        mac_address: bytes) -> epipynet.dhcp.DhcpPacket:

    'Build a DHCP Discover packet'

    discover = epipynet.dhcp.DhcpPacket()
    discover.operation = epipynet.dhcp.DHCP_OPERATION_BOOTREQUEST
    discover.xid = os.getpid()
    discover.flags = epipynet.dhcp.DHCP_FLAG_BROADCAST
    discover.client_hardware_addr = mac_address
    discover.options = [
        (epipynet.dhcp.DHCP_OPTION_TYPE, epipynet.dhcp.DHCP_TYPE_DISCOVER),
        (epipynet.dhcp.DHCP_OPTION_PARAM_REQUEST, struct.pack(
            'BBB',
            epipynet.dhcp.DHCP_OPTION_SUBNET,
            epipynet.dhcp.DHCP_OPTION_ROUTER,
            epipynet.dhcp.DHCP_OPTION_DNS))]

    return discover


def build_dhcp_request(
        offer: epipynet.dhcp.DhcpPacket,
        mac_address: bytes) -> epipynet.dhcp.DhcpPacket:

    'Build a DHCP Request packet in response to a DHCP Offer'

    try:
        offer_server = offer.get_option(epipynet.dhcp.DHCP_OPTION_SERVER)
    except KeyError:
        offer_server = None

    request = epipynet.dhcp.DhcpPacket()
    request.operation = epipynet.dhcp.DHCP_OPERATION_BOOTREQUEST
    request.xid = offer.xid
    request.flags = epipynet.dhcp.DHCP_FLAG_BROADCAST
    request.client_hardware_addr = mac_address
    request.options = [
        (epipynet.dhcp.DHCP_OPTION_TYPE, epipynet.dhcp.DHCP_TYPE_REQUEST),
        (epipynet.dhcp.DHCP_OPTION_IP_REQUEST, offer.your_addr)]

    if offer_server is not None:
        request.options.append(
            (epipynet.dhcp.DHCP_OPTION_SERVER, offer_server))

    return request


def address_list_inet_ntoa(
        addresses: bytes) -> List[str]:

    'Convert multiple binary IPv4 addresses to a list of address strings'

    address_list = []

    while len(addresses) >= 4:
        address = addresses[0:4]
        addresses = addresses[4:]

        address_list.append(socket.inet_ntoa(address))

    return address_list


@asyncio.coroutine
def request_dhcp(
        event_loop: asyncio.AbstractEventLoop,
        local_ip: str,
        dhcp_socket: socket.socket,
        mac_address: bytes) -> NetworkConfigGenerator:

    'Request network configuration via DHCP'

    if local_ip:
        local_ip_addr = socket.inet_aton(local_ip)
    else:
        local_ip_addr = None

    discover = build_dhcp_discover(mac_address)
    offer = yield from exchange_dhcp(
        event_loop,
        dhcp_socket,
        discover,
        epipynet.dhcp.DHCP_TYPE_OFFER,
        local_ip_addr)
    if not offer:
        return None

    syslog.syslog('Got DHCP offer for ' + socket.inet_ntoa(offer.your_addr))

    request = build_dhcp_request(offer, mac_address)
    ack = yield from exchange_dhcp(
        event_loop,
        dhcp_socket,
        request,
        epipynet.dhcp.DHCP_TYPE_ACK,
        local_ip_addr)
    if not ack:
        syslog.syslog('No DHCP ack received')
        return None

    ip_address = socket.inet_ntoa(offer.your_addr)
    try:
        netmask = socket.inet_ntoa(
            offer.get_option(epipynet.dhcp.DHCP_OPTION_SUBNET))
        gateway = socket.inet_ntoa(
            offer.get_option(epipynet.dhcp.DHCP_OPTION_ROUTER))
    except KeyError:
        return None

    try:
        dns_server_bytes = offer.get_option(epipynet.dhcp.DHCP_OPTION_DNS)
    except KeyError:
        dns_server_bytes = b''

    config = epipynet.netconfig.NetworkConfig()
    config.address = ip_address
    config.netmask = netmask
    config.gateway = gateway
    config.dns_servers = address_list_inet_ntoa(dns_server_bytes)

    return config


@asyncio.coroutine
def find_gateway(
        arp_socket: socket.socket,
        arp_reply_listener: ArpReplyListener,
        networks: Iterable[epipynet.netconfig.NetworkConfig]) \
        -> NetworkConfigGenerator:

    '''Send ARP packets to potential gateway addresses until we
    get a response.  on_arp_reply will complete
    self.gateway_network_future to indicate we found a gateway.'''

    gateway_future = asyncio.Future()  # type: asyncio.Future

    while True:
        for network in networks:
            if gateway_future.done():
                return gateway_future.result()

            gateway_address = socket.inet_aton(network.gateway)
            send_arp_request(arp_socket, gateway_address)
            arp_reply_listener.listen_for_ip(
                gateway_address, gateway_future, network)

            yield from asyncio.wait(
                [gateway_future], timeout=ARP_PACKET_TIME)

        yield from asyncio.wait(
            [gateway_future], timeout=ARP_BATCH_TIME)


@asyncio.coroutine
def find_unused_ip(
        arp_socket: socket.socket,
        arp_reply_listener: ArpReplyListener,
        network: epipynet.netconfig.NetworkConfig) \
        -> Generator[Any, None, str]:

    '''Search for an unused IP address on the attacked network
    by generating ARPs, succeeding when several consecutive ARPs
    for an address fail to generate a reply.

    on_arp_reply will complete self.ip_present_future to indicate
    we have a reply on one of our requests.'''

    for ip_address_str in enumerate_subnet_addresses(network):
        syslog.syslog('checking if ' + ip_address_str + ' is used')

        ip_address = socket.inet_aton(ip_address_str)

        ip_present_future = asyncio.Future()  # type: asyncio.Future
        arp_reply_listener.listen_for_ip(
            ip_address, ip_present_future, ip_address_str)

        for i in range(ARP_RETRIES):
            send_arp_request(arp_socket, ip_address)

            yield from asyncio.wait(
                [ip_present_future], timeout=ARP_TIMEOUT)

            if ip_present_future.done():
                break

        if not ip_present_future.done():
            return ip_address_str

    syslog.syslog('no available ip address')
    raise NoAvailableIPAddressException(network)


@asyncio.coroutine
def find_network(
        event_loop: asyncio.AbstractEventLoop,
        local_ip: str,
        arp_socket: socket.socket,
        dhcp_socket: socket.socket,
        networks: Iterable[epipynet.netconfig.NetworkConfig]) \
        -> NetworkConfigGenerator:

    'Locate a gateway and an unused IP address on the attached network'

    mac_address = get_mac_address(arp_socket)

    arp_reply_listener = ArpReplyListener(event_loop, arp_socket)
    arp_reply_listener.start()
    try:
        network = yield from request_dhcp(
            event_loop, local_ip, dhcp_socket, mac_address)

        if network:
            syslog.syslog('acquired DHCP configuration')
            return network
        else:
            syslog.syslog('DHCP acquisition failed')

        network = yield from find_gateway(
            arp_socket, arp_reply_listener, networks)
        syslog.syslog('found gateway at ' + network.gateway)

        config = network.copy()
        if not config.address:
            config.address = yield from find_unused_ip(
                arp_socket, arp_reply_listener, network)

        return config
    finally:
        arp_reply_listener.stop()


def detect_network(
        interface_name: str,
        local_ip: str,
        event_loop: asyncio.AbstractEventLoop,
        networks: Iterable[epipynet.netconfig.NetworkConfig]) \
        -> asyncio.Future:

    'Start scanning for gateways on the network'

    arp_socket = get_ethertype_socket(
        interface_name, epipynet.arp.ETHERTYPE_ARP)
    dhcp_socket = get_dhcp_socket(interface_name)

    found_network_future = event_loop.create_task(find_network(
        event_loop, local_ip, arp_socket, dhcp_socket, networks))

    def on_done(
            future: asyncio.Future) -> None:
        arp_socket.close()
        dhcp_socket.close()

    found_network_future.add_done_callback(on_done)

    return found_network_future


@asyncio.coroutine
def detect_dhcp_server_with_lock(
        interface_name: str,
        local_ip: str,
        event_loop: asyncio.AbstractEventLoop) -> Generator[Any, None, str]:

    '''Return the IP address of a DHCP device on the network,
    other than our local DHCP server.  Return None if we are the
    only DHCP server on the network.'''

    with contextlib.closing(get_ethertype_socket(
                interface_name, epipynet.arp.ETHERTYPE_ARP)) as arp_socket, \
            contextlib.closing(get_dhcp_socket(
                interface_name)) as dhcp_socket:

        mac_address = get_mac_address(arp_socket)
        discover = build_dhcp_discover(mac_address)

        local_ip_addr = socket.inet_aton(local_ip)
        offer = yield from exchange_dhcp(
            event_loop,
            dhcp_socket,
            discover,
            epipynet.dhcp.DHCP_TYPE_OFFER,
            local_ip_addr)

        if offer:
            return socket.inet_ntoa(offer.server_addr)
        else:
            return None


detect_dhcp_lock = asyncio.Lock()
detect_dhcp_result = None  # type: str


@asyncio.coroutine
def detect_dhcp_server(
        interface_name: str,
        local_ip: str,
        event_loop: asyncio.AbstractEventLoop) -> Generator[Any, None, str]:

    '''Detect a DHCP server on the network.

    Use the DHCP lock such that multiple parallel calls to
    detect_dhcp_server will only result in a single detection process.
    The first instance will do the work, and the other invocations will
    use the result from the first invocation when it completes'''

    global detect_dhcp_lock
    global detect_dhcp_result

    if not detect_dhcp_lock.locked():
        with (yield from detect_dhcp_lock):
            detect_dhcp_result = yield from detect_dhcp_server_with_lock(
                interface_name, local_ip, event_loop)
            return detect_dhcp_result
    else:
        with (yield from detect_dhcp_lock):
            return detect_dhcp_result
