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
    """Host object including a hostname and IP.
    """
    yaml_tag = "!Host"
    yaml_loader = yaml.SafeLoader

    hostname: str
    ip: str

    def __post_init__(self):
        ipaddress.ip_address(self.ip)


@dataclass
class Region(yaml.YAMLObject):
    """Region object including the id, name, lists of server hosts, and if port-
    forwarding is supported.
    """
    yaml_tag = "!Region"
    yaml_loader = yaml.SafeLoader

    id: str
    name: str
    port_forward: bool
    servers: list[Host]


@dataclass
class Connection(yaml.YAMLObject):
    """Connection object including everything needed to create a Wireguard
    config file.
    """
    yaml_tag = "!Connection"
    yaml_loader = yaml.SafeLoader

    endpoint: Host
    port: int = None
    ip: str = None
    server_key: str = None
    dns: list[str] = None


@dataclass
class PersistentData(yaml.YAMLObject):
    """Data object including everying relating to the VPN connection that must
    be persisted across runs. Includes helper functions for accessing some data.
    """
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
    last_success: int = 0

    def tokenValid(self) -> bool:
        """Checks if there is a PIA auth token present and if it not expired.

        Returns:
            bool: True if token is present and valid
        """
        not_expired = time.time() < self.token_expiry
        return not_expired and self.token

    def regionsValid(self) -> bool:
        """Checks if there is a list of server regions present and if they are
        not expired.

        Returns:
            bool: True if regions are present and valid
        """
        not_expired = time.time() < self.regions_expiry
        return not_expired and self.regions

    def payloadValid(self) -> bool:
        """Checks if there is a port-forwarind payload and signature present, if
        the payload is in the correct format, and if it is not expired

        Returns:
            bool: True if the payload and signature are present and valid
        """
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
        return not_expired

    def portFromPayload(self) -> int:
        """Extract the port from the port-forwarding payload, if valid.

        Returns:
            int: Port from payload (0 if payload is invalid)
        """
        if not self.payloadValid():
            return 0
        return json.loads(base64.b64decode(self.payload).decode("utf-8"))["port"]


def load(data_file: str) -> PersistentData:
    """Loads a persistent data yaml file.

    Args:
        data_file (str): Data file to load

    Returns:
        PersistentData: Loaded data
    """
    with open(data_file, "r") as f:
        data = yaml.safe_load(f)
        logger.info(f"Loaded VPN data from {data_file}")
        return data


def save(data: PersistentData, data_file: str) -> None:
    """Saves a persistent data yaml file.

    Args:
        data (PersistentData): Data to save
        data_file (str): File to save data into (will be overwritten)

    Raises:
        TypeError: Data is of incorrect type
    """
    if type(data) != PersistentData:
        raise TypeError("Data to save must be of type PersistentData")
    with open(data_file, "w+") as f:
        yaml.dump(data, f)
        logger.debug(f"Saved VPN data to {data_file}")
