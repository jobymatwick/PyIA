#!/usr/bin/env python3

"""Combines config options from the CLI, environment vars, and config file"""

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

import argparse
import yaml
import os
import sys
import logging
import pia_api

CONFIG_DICT = {
    "region": None,
    "username": None,
    "password": None,
    "port_forward": False,
    "port_forward_command": "",
    "log_level": "info",
}

logger = logging.getLogger(__name__)
parser = argparse.ArgumentParser(
    description="Python application for establishing and maintaining Private "
    "Internet Access Wireguard VPN connections."
)

parser.add_argument("-c", "--config", help="Config file to load")
parser.add_argument("-u", "--username", help="PIA account username")
parser.add_argument("-p", "--password", help="PIA account password")
parser.add_argument("-r", "--region", help="ID of server region to connect to")
parser.add_argument("-P", "--port-forward", action="store_true", help="Forward port")
parser.add_argument("-q", "--port-forward-command", help="Run when port changes")
parser.add_argument("-L", "--log-level", help="Application output logging level")
parser.add_argument("-l", "--list-regions", action="store_true", help="List regions")


def get() -> dict:
    """Combine configuration options from CLI flagsm environment variables and
    a config file.

    Returns:
        dict: Populated copy of CONFIG_DICT
    """
    config = CONFIG_DICT
    cli_args = vars(parser.parse_args())
    if cli_args["list_regions"]:
        pia_api.printRegions()
        sys.exit(0)

    if cli_args["config"]:
        try:
            with open(cli_args["config"], "r") as config_file:
                conf_args = yaml.safe_load(config_file)
        except FileNotFoundError:
            logger.error(f"Failed to open config file { cli_args['config'] }")
            sys.exit(1)

    # Config option precedence (1 overrides 2, etc):
    #  1. CLI flags
    #  2. Environment variables
    #  3. Config file
    for key in config.keys():
        if key in cli_args and cli_args[key]:
            config[key] = cli_args[key]
        elif ("PYIA_" + key.upper()) in os.environ:
            config[key] = os.environ["PYIA_" + key.upper()]
        elif cli_args["config"] and key in conf_args:
            config[key] = conf_args[key]

    return config
