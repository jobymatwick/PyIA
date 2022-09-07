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

import configparser
import os
import subprocess
import time
import requests
import logging

from . import vpn_data

WIREGUARD_DIR = "/etc/wireguard"
WIREGUARD_CONFIG = "pia.conf"
NETWORK_IF_DIR = "/sys/class/net/"
IP_CHECK_URL = "https://api.ipify.org"
IP_RETRIES = 3
INFO_KEYS = (
    "pubkey",
    "presharedkey",
    "endpoint",
    "allowedips",
    "handshake",
    "rx",
    "tx",
    "keepalive",
)

logger = logging.getLogger(__name__)


def createKeypair() -> dict[str, str]:
    """Generate a Wireguard keypair.

    Returns:
        dict[str, str]: Keypair dict containing pubkey and prikey items.
    """
    try:
        prikey = subprocess.check_output(["wg", "genkey"]).strip()
        pubkey = subprocess.check_output(["wg", "pubkey"], input=prikey).strip()
    except subprocess.CalledProcessError:
        logger.error("Failed to generate keys with wg. Is wireguard installed?")
        return None

    pair = {"pubkey": pubkey.decode("utf-8"), "prikey": prikey.decode("utf-8")}
    logger.info("Generated a new keypair")

    return pair


def createConfig(connection_info: vpn_data.Connection, prikey: str) -> None:
    """Create a Wireguard configuration file.

    Args:
        connection_info (dict): Connection info to create config using.
        prikey (str): Hosts Wireguard private key
    """
    config = (
        f"[Interface]\n"
        f"Address = {connection_info.ip}\n"
        f"PrivateKey = {prikey}\n"
        f"DNS = {connection_info.dns[0]}\n"
        f"\n"
        f"[Peer]\n"
        f"PersistentKeepalive = 25\n"
        f"PublicKey = {connection_info.server_key}\n"
        f"AllowedIPs = 0.0.0.0/0\n"
        f"Endpoint = {connection_info.endpoint.ip}:{connection_info.port}\n"
    )

    with open(os.path.join(WIREGUARD_DIR, WIREGUARD_CONFIG), "w+") as wg_conf:
        wg_conf.write(config)


def checkConfig() -> bool:
    """Check if a Wireguard config exists.

    Returns:
        bool: True if WIREGUARD_CONFIG is present.
    """
    present = os.path.exists(os.path.join(WIREGUARD_DIR, WIREGUARD_CONFIG))
    logger.debug(f"Wireguard config is{'' if present else ' not'} present.")
    return present


def removeConfig() -> None:
    """Remove the Wiregurd config file from the system, if present. Also brings
    down the interface if it is running"""
    if checkInterface():
        subprocess.run(
            ["/usr/bin/wg-quick", "down", "pia"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if checkConfig():
        os.remove(os.path.join(WIREGUARD_DIR, WIREGUARD_CONFIG))
        logger.debug("Removed wireguard config")


def checkConnection() -> bool:
    """Get the hosts public IP and compare it to the configured connection.
    Returns true of the IPs match and false if they don't or the public IP
    cannot be found.

    Returns:
        bool: True of VPN connection is OK.
    """
    ip = ""
    for attempt in range(IP_RETRIES):
        try:
            raw = requests.get(IP_CHECK_URL, timeout=3).content.decode("utf8")
            ip = ".".join([str(octa) for octa in [int(i) for i in raw.split(".")]])
        except Exception:
            logger.warning(f"Failed to get get public IP.")
        if ip:
            break

    if not ip:
        logger.error(f"Failed to get public IP {IP_RETRIES} times")
        return False
    else:
        logger.info(f"Current public IP is: {ip}")

    expected_ip = getConnectionInfo()["endpoint"]
    if ip == expected_ip:
        logger.info("VPN connection is working")
    else:
        logger.error(f"Expected public IP is: {expected_ip}")
    return ip == expected_ip


def connect() -> bool:
    """Attempt to bring up configured Wireguard connection.

    Returns:
        bool: True if successful or caonnection was already up.
    """
    result = subprocess.run(
        ["/usr/bin/wg-quick", "up", "pia"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if (
        result.returncode != 0
        and f"`{WIREGUARD_CONFIG.rsplit('.', 1)[0]}' already exists"
        not in result.stderr
    ):
        logger.error("Failed to bring up interface")
        for line in result.stdout.decode().splitlines():
            logger.debug(f"  wg-quick: {line}")
        return False
    logger.info("Connection started")
    return True


def checkInterface() -> str:
    try:
        proc = subprocess.run(
            ["wg", "show", "pia", "dump"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        logger.info("Interface pia is not active")
        return ""
    return proc.stdout.decode()


def getConnectionInfo() -> dict[str, str]:
    info = dict(
        zip(
            INFO_KEYS,
            checkInterface().splitlines()[1].split("\t"),
        )
    )

    info["endpoint"] = info["endpoint"].split(":")[0]
    info["handshake"] = f"{int(time.time() - int(info['handshake']))}s ago"
    info["tx"] = _sizeof_fmt(int(info["tx"]))
    info["rx"] = _sizeof_fmt(int(info["rx"]))
    info["keepalive"] += "s"

    return info


def _sizeof_fmt(num: float, suffix: str = "B") -> str:
    """Convert size in base units to human readible format,
    from https://stackoverflow.com/a/1094933.

    Args:
        num: Number to convert (i.e. in bytes)
        suffix: Unit to append to end of string (Defaults to "B")

    Returns:
        str: Human readable size string
    """
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"
