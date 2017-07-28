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

from typing import *


class NetworkConfig(object):

    'Configuration information for the local ethernet network'

    def __init__(self) -> None:

        self.address = None  # type: str
        self.netmask = None  # type: str
        self.gateway = None  # type: str
        self.dns_servers = []  # type: List[str]

    def copy(self):  # type: () -> NetworkConfig

        'Create a copy of a configuration object'

        config = NetworkConfig()

        config.address = self.address
        config.netmask = self.netmask
        config.gateway = self.gateway
        config.dns_servers = self.dns_servers.copy()

        return config

    def to_json(self) -> str:

        'Convert to a JSON representation of the config'

        obj = {
            'host_address': self.address,
            'netmask': self.netmask,
            'gateway': self.gateway,
            'dns_servers': self.dns_servers
        }

        return json.dumps(obj, sort_keys=True, indent=4)


def from_json(
        json_str: str) -> NetworkConfig:

    'Convert from JSON to a NetworkConfig object'

    config = NetworkConfig()
    obj = json.loads(json_str)

    if 'host_address' in obj:
        config.address = obj['host_address']

    if 'netmask' in obj:
        config.netmask = obj['netmask']

    if 'gateway' in obj:
        config.gateway = obj['gateway']

    if 'dns_servers' in obj:
        config.dns_servers = obj['dns_servers']

    return config
