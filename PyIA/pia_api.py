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

import base64
import json
import logging
import os
import subprocess
from typing import Any
import requests
import requests_toolbelt.adapters.host_header_ssl as host_adapter
import time

logger = logging.getLogger(__name__)


class ApiException(RuntimeError):
    pass


class PiaApi:
    TOKEN_LIFE_SECONDS = 3600  # 1 hour
    TOKEN_ADDRESS = "https://www.privateinternetaccess.com/gtoken/generateToken"
    REGION_LIFE_SECONDS = 43200  # 12 hours
    REGION_ADDRESS = "https://serverlist.piaservers.net/vpninfo/servers/v6"
    SSL_CERT_ADDRESS = "https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt"

    def __init__(self, username: str, password: str, data_file: str = "data.json"):
        self.username = username
        self.password = password
        self.data_file = data_file
        self._loadData()

    def token(self) -> str:
        """Get a PIA auth token. Use a stored value if it is OK, otherwise get
        and store a new one.

        Raises:
            ApiException: Request for new token failed

        Returns:
            str: PIA auth token
        """
        stored = self._getStoredToken()
        if stored:
            return stored

        logger.info(f"Fetching a new token for user {self.username}")
        resp = requests.get(
            self.TOKEN_ADDRESS, auth=(self.username, self.password)
        ).json()
        if resp["status"] != "OK":
            raise ApiException(f"Failed to fetch token ({resp['message']})")

        data = self._loadData()
        data["token"] = {
            "user": self.username,
            "expiry_time": time.time() + self.TOKEN_LIFE_SECONDS,
            "key": resp["token"],
        }
        self._saveData(data)
        logger.info("Successfully got new token")
        return data["token"]["key"]

    def regions(self) -> dict[str, dict]:
        """Get a list of PIA server regions. Uses a cached list and refreshes
        when stale.

        Raises:
            ApiException: Failed to get region list from PIA

        Returns:
            dict[str, dict]: Dict of regions, keys are region ids
        """
        stored = self._getStoredRegions()
        if stored:
            return stored

        logger.info("Fetching new region list")
        resp = requests.get(self.REGION_ADDRESS)
        if resp.status_code != 200:
            raise ApiException(
                f"Failed to get region info file. ({ resp.status_code })"
            )
        if len(resp.text) < 1000:
            raise ApiException(f"Region info file is suspiciously short.")

        raw_regions = json.loads(resp.text.splitlines()[0])
        regions = {}
        for item in raw_regions["regions"]:
            if "wg" not in item["servers"]:
                continue
            regions[item["id"]] = {
                "name": item["name"],
                "port_forward": item["port_forward"],
                "servers": [
                    (server["cn"], server["ip"]) for server in item["servers"]["wg"]
                ],
            }
        regions["expiry_time"] = time.time() + self.REGION_LIFE_SECONDS
        data = self._loadData()
        data["regions"] = regions
        self._saveData(data)
        return regions

    def authenticate(
        self, region: str, pubkey: str, server_id: int = 0
    ) -> dict[str, str]:
        """Authenticate a Wireguard public key on a PIA server.

        Args:
            region (str): Server region id to authenticate with
            pubkey (str): Wireguard pubkey to authenticate
            server_id (int, optional): Server IP index. Defaults to 0.

        Raises:
            ValueError: Invalid region id
            ApiException: Authentication failed

        Returns:
            dict[str, str]: Connection info required to configure Wireguard
        """
        self._getCert()

        regions = self.regions()
        if region not in regions:
            raise ValueError(f'Region ID "{region}" not found')

        sess = requests.Session()
        sess.mount("https://", host_adapter.HostHeaderSSLAdapter())
        resp = sess.get(
            f"https://{ regions[region]['servers'][server_id][1] }:1337/addKey",
            verify="ca.rsa.4096.crt",
            params={"pt": self.token(), "pubkey": pubkey},
            headers={"Host": regions[region]["servers"][server_id][0]},
        ).json()

        if resp["status"] != "OK":
            raise ApiException(f"Failed to authenticate ({resp['message']})")

        connection_info = {
            "address": resp["peer_ip"],
            "dns": resp["dns_servers"][0],
            "pubkey": resp["server_key"],
            "host": regions[region]["servers"][server_id][0],
            "endpoint": f"{ resp['server_ip'] }:{ str(resp['server_port']) }",
        }
        logger.info(
            f"Authenticated {connection_info['pubkey']} on {connection_info['host']}"
        )
        return connection_info

    def portForward(self, connection_info: dict[str, Any], command: str) -> bool:
        signature, changed = self._getSignature(connection_info)
        bound = self._bindPort(
            signature,
            connection_info["endpoint"].split(":")[0],
            connection_info["host"],
        )
        if bound and changed:
            subprocess.check_output(command.split(" "))
            logger.info("Port change command ran")
        return bound

    def _loadData(self) -> dict[str, Any]:
        if not os.path.exists(self.data_file):
            with open(self.data_file, "w+") as f:
                f.write("{}\n")

        with open(self.data_file, "r") as f:
            return json.load(f)

    def _saveData(self, data: dict[str, Any]):
        with open(self.data_file, "w+") as f:
            json.dump(data, f)

    def _getStoredToken(self) -> str:
        data = self._loadData()
        if "token" not in data:
            logger.debug("No stored token found")
        elif data["token"]["user"] != self.username:
            logger.debug("Stored token is for a different user")
        elif data["token"]["expiry_time"] < time.time():
            logger.debug("Stored token is stale")
        else:
            valid_m = int((data["token"]["expiry_time"] - time.time()) / 60)
            logger.debug(f"Valid token found (good for {valid_m} more minute(s))")
            return data["token"]["key"]
        return ""

    def _getStoredRegions(self) -> dict[str, dict]:
        data = self._loadData()
        if "regions" not in data:
            logger.debug("No stored regions found")
        elif data["regions"]["expiry_time"] < time.time():
            logger.debug("Stored regions are stale")
        else:
            valid_m = int((data["regions"]["expiry_time"] - time.time()) / 60)
            logger.debug(f"Stored regions found (good for {valid_m} more minute(s))")
            return data["regions"]
        return []

    def _getSignature(self, connection_info: dict[str, Any]) -> tuple[dict, bool]:
        data = self._loadData()
        if "signature" not in data:
            logger.debug("No stored signature found")
        elif data["signature"]["expiry_time"] < time.time():
            logger.debug("Stored signature is stale")
        else:
            valid_h = int((data["signature"]["expiry_time"] - time.time()) / 3600 * 24)
            logger.debug(f"Valid signature found (good for {valid_h} more days(s))")
            return data["signature"], False

        self._getCert()
        sess = requests.Session()
        sess.mount("https://", host_adapter.HostHeaderSSLAdapter())
        resp = sess.get(
            f"https://{connection_info['endpoint'].split(':')[0]}:19999/getSignature",
            verify="ca.rsa.4096.crt",
            params={"token": self.token()},
            headers={"Host": connection_info["host"]},
        ).json()

        if resp["status"] != "OK":
            raise RuntimeError(f"Failed to get signature ({resp['message']})")

        stored = json.loads(base64.b64decode(resp["payload"]))
        stored["signature"] = resp["signature"]
        stored["payload"] = resp["payload"]
        data = self._loadData()
        data["signature"] = stored
        self._saveData(data)
        return data, True

    def _getCert(self) -> None:
        if os.path.exists("ca.rsa.4096.crt"):
            return
        logger.info("Downloading PIA SSL certificate.")
        with open("ca.rsa.4096.crt", "w+") as cert_file:
            cert_file.write(requests.get(self.SSL_CERT_ADDRESS).text)

    def _bindPort(self, signature: dict[str, str], ip: str, host: str) -> bool:
        logger.info(f"Binding port {signature['port']}")
        sess = requests.Session()
        sess.mount("https://", host_adapter.HostHeaderSSLAdapter())
        resp = sess.get(
            f"https://{ip}:19999/bindPort",
            verify="ca.rsa.4096.crt",
            params={
                "payload": signature["payload"],
                "signature": signature["signature"],
            },
            headers={"Host": host},
        ).json()

        if resp["status"] != "OK":
            logger.error(f"Failed to bind port {resp['message']}")
            return False
        return True
