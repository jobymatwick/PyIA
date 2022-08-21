#!/usr/bin/env python3

"""Functions to interface with Wireguard"""

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
import os
import subprocess
import requests
import logging

WIREGUARD_DIR = "/etc/wireguard"
IP_RETRIES = 3

logger = logging.getLogger(__name__)


def createConfig(connection_info: dict, prikey: str) -> None:
    """Create a Wireguard configuration file.

    Args:
        connection_info (dict): Connection info to create config using.
        prikey (str): Hosts Wireguard private key
    """
    config = (
        f"[Interface]\n"
        f'Address = { connection_info["address"] }\n'
        f"PrivateKey = { prikey }\n"
        f'DNS = { connection_info["dns"][0] }\n'
        f"\n"
        f"[Peer]\n"
        f"PersistentKeepalive = 25\n"
        f'PublicKey = { connection_info["pubkey"] }\n'
        f"AllowedIPs = 0.0.0.0/0\n"
        f'Endpoint = { connection_info["endpoint"] }\n'
    )

    with open(os.path.join(WIREGUARD_DIR, "pia.conf"), "w+") as wg_conf:
        wg_conf.write(config)
    with open("connection.json", "w+") as conn_bkp:
        json.dump(connection_info, conn_bkp)


def createKeypair() -> dict[str, str]:
    """Generate a Wireguard keypair.

    Returns:
        dict[str, str]: Keypair dict containing pubkey and prikey items.
    """
    prikey = subprocess.check_output(["wg", "genkey"]).strip()
    pubkey = subprocess.check_output(["wg", "pubkey"], input=prikey).strip()
    pair = {"pubkey": pubkey.decode("utf-8"), "prikey": prikey.decode("utf-8")}
    logger.info("Generated a new keypair")

    return pair


def checkConnection() -> bool:
    """Get the hosts public IP and compare it to the configured connection.
    Returns true of the IPs match and false if they don't or the public IP
    cannot be found.

    Returns:
        bool: True of VPN connection is OK.
    """
    retries = IP_RETRIES
    ip = ""

    while not ip and retries:
        try:
            ip = requests.get("https://api.ipify.org", timeout=3).content.decode("utf8")
        except Exception as e:
            retries = retries - 1
            logger.warn(f"Failed to get get public IP.")
    if not retries:
        return False

    with open("connection.json", "r") as connection:
        target_ip = json.load(connection)["endpoint"].split(":")[0]
    if ip == target_ip:
        logger.info("Connection OK")
    else:
        logger.error(f"IP mismatch. Public: { ip }, Expected: { target_ip }")
    return ip == target_ip


def checkConfig() -> bool:
    """Check if a Wireguard config exists.

    Returns:
        bool: True if pia.conf is present.
    """
    present = os.path.exists(os.path.join(WIREGUARD_DIR, "pia.conf"))
    logger.debug(f"Wireguard config is { '' if present else 'not' } present.")
    return present

def checkInterface() -> bool:
    """Check if Wireguard interface is active.

    Returns:
        bool: True if interface is active.
    """
    active = 'pia' in os.listdir('/sys/class/net/')
    logger.debug(f"Wireguard interface is { 'active' if active else 'inactive' }.")
    return active

def connect() -> bool:
    result = subprocess.run(['/usr/bin/wg-quick', 'up', 'pia'])
    if result.returncode != 0:
        logger.error("Failed to bring up interface")
        return False
    logger.info("Connection started")
    return True
