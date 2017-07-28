#!/usr/bin/env python3
#
#    epipynet - Epipylon network configuration
#    Copyright (C) 2017  Matt Kimball
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import json
import os
import select
import socket
import subprocess
import time
import unittest

from typing import *

import epipynet.arp
import epipynet.dhcp


TEST_ARP_PORT = 4044
TEST_DHCP_PORT = 4045
TEST_CONFIG_PATH = '/tmp/epipynet/config.json'


AddressPair = Tuple[str, int]


def wait_for_json(
        path: str,
        timeout: int) -> Dict:

    'Poll every 100 ms for the creation of a JSON file, with a timeout'

    for i in range(timeout * 10):
        try:
            os.stat(path)
            break
        except FileNotFoundError:
            pass

        time.sleep(0.1)

    with open(path) as json_file:
        result = json.loads(json_file.read())

    os.unlink(path)
    return result


def receive_dhcp(
        sock: socket.socket
        ) -> Tuple[epipynet.dhcp.DhcpPacket, AddressPair]:

    'Wait for a DHCP packet to arrive, with a timeout'

    (readlist, writelist, exclist) = select.select([sock], [], [], 30)

    if sock not in readlist:
        raise TimeoutError(sock)

    (packet_bytes, remote_addr) = sock.recvfrom(4096)
    packet = epipynet.dhcp.decode(packet_bytes)

    return (packet, remote_addr)


def build_dhcp_offer(
        discover: epipynet.dhcp.DhcpPacket) -> epipynet.dhcp.DhcpPacket:

    'Build a DHCP Offer packet in response to a DHCP Discover'

    offer = epipynet.dhcp.DhcpPacket()
    offer.operation = epipynet.dhcp.DHCP_OPERATION_BOOTREPLY
    offer.xid = discover.xid
    offer.your_addr = socket.inet_aton('192.168.1.100')
    offer.server_addr = socket.inet_aton('192.168.1.3')
    offer.client_hardware_addr = discover.client_hardware_addr
    offer.options = [
        (epipynet.dhcp.DHCP_OPTION_TYPE, epipynet.dhcp.DHCP_TYPE_OFFER),
        (epipynet.dhcp.DHCP_OPTION_SUBNET,
            socket.inet_aton('255.255.255.128')),
        (epipynet.dhcp.DHCP_OPTION_ROUTER,
            socket.inet_aton('192.168.1.2')),
        (epipynet.dhcp.DHCP_OPTION_SERVER,
            socket.inet_aton('192.168.1.3')),
        (epipynet.dhcp.DHCP_OPTION_DNS,
            socket.inet_aton('4.3.2.1') +
            socket.inet_aton('4.3.2.2') +
            socket.inet_aton('4.3.2.3'))]

    return offer


def build_dhcp_ack(
        request: epipynet.dhcp.DhcpPacket) -> epipynet.dhcp.DhcpPacket:

    'Build a DHCP Ack packet in response to a DHCP Request'

    ack = epipynet.dhcp.DhcpPacket()
    ack.operation = epipynet.dhcp.DHCP_OPERATION_BOOTREPLY
    ack.xid = request.xid
    ack.your_addr = request.get_option(epipynet.dhcp.DHCP_OPTION_IP_REQUEST)
    ack.server_addr = socket.inet_aton('192.168.1.3')
    ack.client_hardware_addr = request.client_hardware_addr
    ack.options = [
        (epipynet.dhcp.DHCP_OPTION_TYPE, epipynet.dhcp.DHCP_TYPE_ACK),
        (epipynet.dhcp.DHCP_OPTION_SUBNET,
            socket.inet_aton('255.255.255.128')),
        (epipynet.dhcp.DHCP_OPTION_ROUTER,
            socket.inet_aton('192.168.1.2')),
        (epipynet.dhcp.DHCP_OPTION_SERVER,
            socket.inet_aton('192.168.1.3')),
        (epipynet.dhcp.DHCP_OPTION_DNS,
            socket.inet_aton('4.3.2.1') +
            socket.inet_aton('4.3.2.2') +
            socket.inet_aton('4.3.2.3'))]

    return ack


class NetDetectTest(unittest.TestCase):

    'Test that gateway detection works using ARP and DHCP'

    def __init__(self, *args) -> None:
        self.arp_socket = None  # type: socket.socket
        self.proc = None  # type: subprocess.Popen

        super(NetDetectTest, self).__init__(*args)

    def setUp(self) -> None:

        'Bind a UDP testing socket and spin up an autoconfigure process'

        try:
            os.unlink(TEST_CONFIG_PATH)
        except OSError:
            pass

        self.arp_socket = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.dhcp_socket = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        self.arp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.arp_socket.bind(('localhost', TEST_ARP_PORT))
        self.dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.dhcp_socket.bind(('localhost', TEST_DHCP_PORT))

        env = os.environ
        env['EPIPYNET_TEST'] = '1'

        self.proc = subprocess.Popen('bin/epipynet-autoconfigure', env=env)

    def tearDown(self) -> None:

        'Close our socket and process from setUp'

        self.arp_socket.close()
        self.arp_socket = None

        self.dhcp_socket.close()
        self.dhcp_socket = None

        self.proc.kill()
        self.proc = None

    def test_arp(self) -> None:

        '''Reply to the first ARP request and test that the network config
        is generated'''

        (readlist, writelist, exclist) = \
            select.select([self.arp_socket], [], [], 30)

        self.assertIn(self.arp_socket, readlist)
        (packet_bytes, recv_addr) = self.arp_socket.recvfrom(4096)

        packet = epipynet.arp.decode(packet_bytes)
        self.assertEqual(packet.operation, epipynet.arp.ARP_OPERATION_REQUEST)

        reply = epipynet.arp.ArpPacket()
        reply.destination = packet.source
        reply.operation = epipynet.arp.ARP_OPERATION_REPLY
        reply.sender_protocol_addr = packet.target_protocol_addr
        reply.target_protocol_addr = packet.sender_protocol_addr
        reply.target_hardware_addr = packet.sender_hardware_addr

        self.arp_socket.sendto(reply.encode(), recv_addr)

        config = wait_for_json(TEST_CONFIG_PATH, 10)
        self.assertIn('host_address', config)
        self.assertIn('netmask', config)
        self.assertIn('gateway', config)

        gateway_addr = socket.inet_ntoa(reply.sender_protocol_addr)
        self.assertEqual(config['gateway'], gateway_addr)
        self.assertIn(gateway_addr, config['dns_servers'])

    def test_dhcp(self) -> None:

        'Simluate a DHCP server to test DHCP acquired configuration'

        (discover, discover_addr) = receive_dhcp(self.dhcp_socket)
        self.assertEqual(
            discover.get_option(epipynet.dhcp.DHCP_OPTION_TYPE),
            epipynet.dhcp.DHCP_TYPE_DISCOVER)

        offer = build_dhcp_offer(discover)
        self.dhcp_socket.sendto(offer.encode(), discover_addr)

        (request, request_addr) = receive_dhcp(self.dhcp_socket)
        self.assertEqual(
            request.get_option(epipynet.dhcp.DHCP_OPTION_TYPE),
            epipynet.dhcp.DHCP_TYPE_REQUEST)

        ack = build_dhcp_ack(request)
        self.dhcp_socket.sendto(ack.encode(), request_addr)

        config = wait_for_json(TEST_CONFIG_PATH, 10)
        self.assertEqual(config['host_address'], '192.168.1.100')
        self.assertEqual(config['netmask'], '255.255.255.128')
        self.assertEqual(config['gateway'], '192.168.1.2')
        self.assertIn('4.3.2.2', config['dns_servers'])


if __name__ == '__main__':
    unittest.main()
