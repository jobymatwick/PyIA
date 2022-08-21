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
import requests
import requests_toolbelt.adapters.host_header_ssl as host_adapter
import time

TOKEN_LIFE_SECONDS = 3600  # 1 hour
TOKEN_ADDRESS = "https://www.privateinternetaccess.com/gtoken/generateToken"
TOKEN_FILE = "token.json"

REGION_LIFE_SECONDS = 43200  # 12 hours
REGION_ADDRESS = "https://serverlist.piaservers.net/vpninfo/servers/v6"
REGION_FILE = "regions.json"

SSL_CERT_ADDRESS = "https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt"
SSL_CERT_FILE = "ca.rsa.4096.crt"

logger = logging.getLogger(__name__)


def getToken(creds: dict[str:str]) -> str:
    """Get a PIA auth token. Returns a stored token if found and still valid,
    otherwise attempts to generate and store a new one.

    Args:
        creds (dict[str:str]): PIA credentials. Dict must have 'user' and 'pass'
        keys.

    Raises:
        RuntimeError: Occurs when failed to get a token.

    Returns:
        str: Stored or generated PIA auth token.
    """
    try:
        with open(TOKEN_FILE, "r") as token_file:
            token = json.load(token_file)

        exp_time = token["time"] + TOKEN_LIFE_SECONDS
        now_time = time.time()
        if token["user"] != creds["user"]:
            logger.debug(f"Token file is for different user")
        elif exp_time < now_time:
            logger.debug(f"Toek file is stale")
        else:
            logger.debug(
                f'Found valid token "{ token["token"][:10] }..." '
                f'for user { creds["user"] } '
                f"valid for { int(exp_time - now_time) } more seconds."
            )
            return token["token"]
    except FileNotFoundError:
        logger.debug(f"{ TOKEN_FILE } not found")
        pass
    else:
        os.remove(TOKEN_FILE)

    logger.info(f'Fetching new token for user "{ creds["user"] }".')
    req = requests.get(TOKEN_ADDRESS, auth=(creds["user"], creds["pass"]))
    data = req.json()
    if data["status"] != "OK":
        raise RuntimeError(f'Failed to get token ({ data["message"] })')

    token = {
        "time": time.time(),
        "token": data["token"],
        "user": creds["user"],
    }
    logger.info(f'Got token "{ token["token"][:10] }..."')
    with open(TOKEN_FILE, "w+") as token_file:
        json.dump(token, token_file)
    return token["token"]


def getRegionInfo(region: str) -> dict:
    """Get the server info for a given server region.

    Args:
        region (str): ID of region to get info of.

    Returns:
        dict: Region server info including name, IPs, hostnames, and port.
    """
    regions = _getRegions()
    raw_info = next(item for item in regions["regions"] if item["id"] == region)
    region_info = {
        "name": raw_info["name"],
        "servers": raw_info["servers"]["wg"],
        "port": regions["groups"]["wg"][0]["ports"][0],
    }
    return region_info


def authenticate(region_info: dict, token: str, pubkey: str, ip_id: int = 0) -> dict:
    """Attempt to authenticate a Wireguard pubkey with a PIA server, and get the
    connection info if successful.

    Args:
        region_info (dict): Server to authenticate with.
        token (str): PIA auth token to use.
        pubkey (str): Wireguard client pubkey to authenticate.
        ip_id (int, optional): Index of server to use. Defaults to 0.

    Raises:
        RuntimeError: Failed to authenticate.

    Returns:
        dict: Connection info required to generate a Wireguard config.
    """
    if not os.path.exists(SSL_CERT_FILE):
        logger.info("Downloading PIA SSL certificate.")
        cert = requests.get(SSL_CERT_ADDRESS).text
        with open(SSL_CERT_FILE, "w+") as cert_file:
            cert_file.write(cert)

    server = region_info["servers"][ip_id]

    logger.info(
        f'Attempting to authenticate key "{ pubkey }" on server '
        f'{ server["cn"] } ({ server["ip"] })'
    )
    sess = requests.Session()
    sess.mount("https://", host_adapter.HostHeaderSSLAdapter())
    req = sess.get(
        f"https://{ server['ip'] }:{ region_info['port'] }/addKey",
        verify=SSL_CERT_FILE,
        params={"pt": token, "pubkey": pubkey},
        headers={"Host": server["cn"]},
    )

    data = req.json()
    if data["status"] != "OK":
        raise RuntimeError(f'Failed to authenticate key ({ data["message"] })')

    connection_info = {
        "address": data["peer_ip"],
        "dns": data["dns_servers"],
        "pubkey": data["server_key"],
        "host": server["cn"],
        "endpoint": f"{ data['server_ip'] }:{ str(data['server_port']) }",
    }
    return connection_info


def printRegions() -> None:
    """Print a list of all server regions and whether or not they support port
    forwarding.
    """
    regions = sorted(_getRegions()["regions"], key=lambda d: d["id"])
    print("Listing all regions. (*) means regions supports port forwarding.\n")
    print("  Region ID             Region Name")
    print("---------------------------------------------")
    for region in regions:
        print(
            f'{ "*" if region["port_forward"] else " " } { region["id"] :22}'
            f'{ region["name"] }'
        )


def _getRegions() -> dict:
    """Get a list of all server regions. Uses a cached region file, and replaces
    it if stale.

    Raises:
        RuntimeError: Failed to get region info from server.
        ValueError: Region info received appears to be invalid.

    Returns:
        dict: All server regions.
    """
    stale = True
    try:
        with open(REGION_FILE, "r") as region_file:
            regions = json.load(region_file)

        exp_time = regions["time"] + REGION_LIFE_SECONDS
        now_time = time.time()
        if exp_time > now_time:
            logger.debug("Found valid region file")
            stale = False
    except FileNotFoundError:
        pass

    if stale:
        logger.info(f"Fetching new region info file.")
        req = requests.get(REGION_ADDRESS)
        if req.status_code != 200:
            raise RuntimeError(f"Failed to get region info file. ({ req.status_code })")
        if len(req.text) < 1000:
            raise ValueError(f"Region info file is suspiciously short.")
        regions = json.loads(req.text.splitlines()[0])
        regions["time"] = time.time()

        with open(REGION_FILE, "w+") as region_file:
            json.dump(regions, region_file)

    return regions
