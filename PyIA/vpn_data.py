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

import base64
from dataclasses import dataclass
import datetime
import ipaddress
import json
import logging
import time
import yaml

logger = logging.getLogger(__name__)


@dataclass
class Host(yaml.YAMLObject):
    yaml_tag = "!Host"
    yaml_loader = yaml.SafeLoader

    hostname: str
    ip: str

    def __post_init__(self):
        ipaddress.ip_address(self.ip)


@dataclass
class Region(yaml.YAMLObject):
    yaml_tag = "!Region"
    yaml_loader = yaml.SafeLoader

    id: str
    name: str
    port_forward: bool
    servers: list[Host]


@dataclass
class Connection(yaml.YAMLObject):
    yaml_tag = "!Connection"
    yaml_loader = yaml.SafeLoader

    endpoint: Host
    port: int = None
    ip: str = None
    server_key: str = None
    dns: list[str] = None


@dataclass
class PersistentData(yaml.YAMLObject):
    yaml_tag = "!PersistentData"
    yaml_loader = yaml.SafeLoader

    username: str = None
    token: str = None
    token_expiry: int = 0
    regions: list[Region] = None
    regions_expiry: int = 0
    connection: Connection = None
    port: int = None
    signature: str = None
    payload: str = None

    def tokenValid(self) -> bool:
        not_expired = time.time() < self.token_expiry
        return not_expired and self.token

    def regionsValid(self) -> bool:
        not_expired = time.time() < self.regions_expiry
        return not_expired and self.regions

    def payloadValid(self) -> bool:
        if not self.payload or not self.signature:
            return False
        try:
            data = json.loads(base64.b64decode(self.payload).decode("utf-8"))
            not_expired = (
                time.time()
                < datetime.datetime.fromisoformat(data["expires_at"][:-4]).timestamp()
            )
        except Exception:
            return False
        return not_expired and data["signature"] == self.signature

    def portFromPayload(self) -> int:
        if not self.payloadValid():
            return 0
        return json.loads(base64.b64decode(self.payload).decode("utf-8"))["port"]


def load(data_file: str) -> PersistentData:
    with open(data_file, "r") as f:
        data = yaml.safe_load(f)
        logger.info(f"Loaded VPN data from {data_file}")
        return data


def save(data: PersistentData, data_file: str) -> None:
    if type(data) != PersistentData:
        raise TypeError("Data to save must be of type PersistentData")
    with open(data_file, "w+") as f:
        yaml.dump(data, f)
        logger.debug(f"Saved VPN data to {data_file}")
