#!/usr/bin/env python3

"""Classes to store VPN-related data"""

# PyIA
# Copyright (C) 2022  Joby Matwick
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <http://www.gnu.org/licenses/>.

from dataclasses import dataclass
import ipaddress
import yaml

@dataclass
class Host(yaml.YAMLObject):
    yaml_tag = u'!Host'
    yaml_loader = yaml.SafeLoader

    hostname: str
    ip: str

    def __post_init__(self):
        ipaddress.ip_address(self.ip)

@dataclass
class Region(yaml.YAMLObject):
    yaml_tag = u'!Region'
    yaml_loader = yaml.SafeLoader

    id: str
    name: str
    port_forward: bool
    servers: list[Host]

@dataclass
class PersistentData(yaml.YAMLObject):
    yaml_tag = u'!PersistentData'
    yaml_loader = yaml.SafeLoader

    username: str = None
    token: str = None
    token_expiry: int = None
    regions: list[str, Region] = None
    regions_expiry: int = None
    connection: Host = None
    port: int = None

def load(data_file: str) -> PersistentData:
    with open(data_file, 'r') as f:
        return yaml.safe_load(f)

def save(data: PersistentData, data_file: str):
    if type(data) != PersistentData:
        raise TypeError("Data to save must be of type PersistentData")
    with open(data_file, 'w+') as f:
        yaml.dump(data, f)
