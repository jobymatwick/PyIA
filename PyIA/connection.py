#!/usr/bin/env python3

"""Checks for an active connection and starts one if needed"""

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

import logging
from typing import Any

from . import wireguard
from . import pia_api

CONNECTION_ATTEMPTS = 3

logger = logging.getLogger(__name__)


def updateConnection(config: dict[str, Any]) -> bool:
    """Connection management logic. If no connection is active this will try to
    establish one, otherwise it will attempt to refresh the connection.

    Args:
        config (dict[str, Any]): App configuration from config.py

    Returns:
        bool: True if connection is active
    """
    connected = False
    api = pia_api.PiaApi(config["username"], config["password"])

    for i in range(CONNECTION_ATTEMPTS):
        logger.info(f"Starting connection attempt {i + 1}...")
        if not wireguard.checkInterface():
            try:
                logger.info("Generating a new config")
                keypair = wireguard.createKeypair()
                conn_info = api.authenticate(config["region"], keypair["pubkey"])
                wireguard.createConfig(conn_info, keypair["prikey"])
                wireguard.connect()
            except pia_api.ApiException or ValueError as e:
                logger.error(f"Auth error: {str(e)}")
                continue

        connected = wireguard.checkConnection()
        if not connected:
            wireguard.removeConfig()
        else:
            logger.info(f"Successfully connected on attempt {i + 1}")
            api.portForward(config["port_forward_command"])
            api.storeSuccess()
            break
    return connected
