#!/usr/bin/env python3

"""Functions to interface with Private Internet Access's APIs"""

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

import json
import logging
import os
import subprocess
import requests
import requests_toolbelt.adapters.host_header_ssl as host_adapter
import time

from . import vpn_data

logger = logging.getLogger(__name__)


class ApiException(RuntimeError):
    pass


class PiaApi:
    """Class to interface with PIA's APIs."""

    TOKEN_LIFE_SECONDS = 3600  # 1 hour
    TOKEN_ADDRESS = "https://www.privateinternetaccess.com/gtoken/generateToken"
    REGION_LIFE_SECONDS = 43200  # 12 hours
    REGION_ADDRESS = "https://serverlist.piaservers.net/vpninfo/servers/v6"
    SSL_CERT_ADDRESS = "https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt"
    PORT_TEMPLATE = "{{PORT}}"

    def __init__(self, username: str, password: str, data_file: str = "data.yml"):
        """Load any data from previous usage if present and store credentials.

        Args:
            username (str): PIA username
            password (str): PIA password
            data_file (str, optional): Persistent data file. Defaults to "data.yml".
        """
        self.username = username
        self.password = password
        self.data_file = data_file
        try:
            data = vpn_data.load(self.data_file)
            if data.username == username or not username:
                self.data = data
            else:
                logger.info("Saved VPN data does not match current user.")
                self.data = vpn_data.PersistentData()
        except FileNotFoundError:
            self.data = vpn_data.PersistentData()

    def token(self) -> str:
        """Get a PIA auth token. Use a stored value if it is OK, otherwise get
        and store a new one.

        Raises:
            ApiException: Request for new token failed

        Returns:
            str: PIA auth token
        """
        if self.data.tokenValid():
            return self.data.token

        logger.info(f"Fetching a new token for user {self.username}")
        resp = requests.get(
            self.TOKEN_ADDRESS, auth=(self.username, self.password)
        ).json()
        if resp["status"] != "OK":
            raise ApiException(f"Failed to fetch token ({resp['message']})")

        self.data.token = resp["token"]
        self.data.token_expiry = int(time.time() + self.TOKEN_LIFE_SECONDS)
        self.data.username = self.username

        logger.info("Successfully got new token")
        vpn_data.save(self.data, self.data_file)
        return self.data.token

    def regions(self) -> list[vpn_data.Region]:
        """Get a list of PIA server regions.

        Raises:
            ApiException: Failed to get region list from PIA

        Returns:
            list[vpn_data.Region]: List of valid regions
        """
        logger.info("Fetching server region list")
        resp = requests.get(self.REGION_ADDRESS)
        if resp.status_code != 200:
            raise ApiException(f"Failed to get region file. ({ resp.status_code })")
        if len(resp.text) < 1000:
            raise ApiException(f"Region info file is suspiciously short.")

        raw_regions = json.loads(resp.text.splitlines()[0])
        regions: list[vpn_data.Region] = []
        for item in raw_regions["regions"]:
            if "wg" not in item["servers"]:
                continue
            regions.append(
                vpn_data.Region(
                    item["id"],
                    item["name"],
                    item["port_forward"],
                    [
                        vpn_data.Host(server["cn"], server["ip"])
                        for server in item["servers"]["wg"]
                    ],
                )
            )
        regions.sort(key=lambda x: x.id)

        logger.info(f"Successfully got region list containing {len(regions)} regions")
        return regions

    def authenticate(
        self, region_id: str, pubkey: str, server_id: int = 0
    ) -> vpn_data.Connection:
        """Authenticate a Wireguard public key on a PIA server.

        Args:
            region (str): Server region id to authenticate with
            pubkey (str): Wireguard pubkey to authenticate
            server_id (int, optional): Server IP index. Defaults to 0.

        Raises:
            ValueError: Invalid region id
            ApiException: Authentication failed

        Returns:
            Connection: Connection info required to configure Wireguard
        """
        try:
            region = next(item for item in self.regions() if item.id == region_id)
        except StopIteration:
            raise ValueError(f'Region ID "{region_id}" not found')

        self.data.connection = vpn_data.Connection(region.servers[server_id])
        resp = self._sslGet(
            1337, "addKey", {"pt": self.token(), "pubkey": pubkey}
        ).json()

        if resp["status"] != "OK":
            raise ApiException(f"Failed to authenticate ({resp['message']})")

        self.data.connection = vpn_data.Connection(
            endpoint=region.servers[server_id],
            port=int(resp["server_port"]),
            ip=resp["peer_ip"],
            server_key=resp["server_key"],
            dns=resp["dns_servers"],
        )

        logger.info(f"Authenticated on {self.data.connection.endpoint.hostname}")
        vpn_data.save(self.data, self.data_file)
        return self.data.connection

    def portForward(self, command: str = None) -> None:
        """Establish or refresh port forwarding for the active VPN connection.

        Args:
            command (str, optional): Command to run when the port is bound or
                changed. Defaults to None.

        Raises:
            ApiException: Failed to get a signature and payload
            ApiException: Signature and payload are invalid
            ApiException: Failed to bind port
        """
        new_port = False
        if not self.data.payloadValid():
            resp = self._sslGet(19999, "getSignature", {"token": self.token()}).json()
            if resp["status"] != "OK":
                raise ApiException(f"Failed to get signature ({resp['message']})")
            self.data.signature = resp["signature"]
            self.data.payload = resp["payload"]
            if not self.data.payloadValid():
                raise ApiException("Got an invalid signature")
            new_port = True

        port = self.data.portFromPayload()
        logger.info(f"Binding port {port}")
        resp = self._sslGet(
            19999,
            "bindPort",
            {"payload": self.data.payload, "signature": self.data.signature},
        ).json()

        if resp["status"] != "OK":
            raise ApiException(f"Failed to bind port ({resp['message']})")
        logger.info("Port bound successfully")
        vpn_data.save(self.data, self.data_file)

        if new_port and command:
            command_str = command.replace(self.PORT_TEMPLATE, str(port))
            logger.info(f'Running "{command_str}"')
            subprocess.check_output(command_str.split(" "))
            logger.info("Port change command ran")

    def storeSuccess(self) -> None:
        """Stores the current time into the persistent data file.
        """
        self.data.last_success = int(time.time())
        vpn_data.save(self.data, self.data_file)

    def _sslGet(
        self, port: int, path: str, params: dict[str, str]
    ) -> requests.Response:
        """Make an HTTPS GET request to the currently connected server with the
        SSL certificate from PIA. The certificate will be downloaded if not
        present.

        Args:
            port (int): Port of service to send request to
            path (str): Path to send request to
            params (dict[str, str]): URL params to include in request

        Returns:
            requests.Response: Request response
        """
        if not os.path.exists("ca.rsa.4096.crt"):
            logger.info("Downloading PIA SSL certificate.")
            with open("ca.rsa.4096.crt", "w+") as cert_file:
                cert_file.write(requests.get(self.SSL_CERT_ADDRESS).text)

        sess = requests.Session()
        sess.mount("https://", host_adapter.HostHeaderSSLAdapter())

        url = f"https://{self.data.connection.endpoint.ip}:{port}/{path}"
        headers = {"Host": self.data.connection.endpoint.hostname}
        return sess.get(url, verify="ca.rsa.4096.crt", params=params, headers=headers)
