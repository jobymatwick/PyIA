#!/usr/bin/env python3

"""Python application for establishing and maintaining Private Internet Access
Wireguard VPN connections."""

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
import logging
import sys

from PyIA import requirements


def main(arguments: list[str]) -> int:
    """Main application entry point

    Args:
        arguments (list[str]): Raw CLI arguments

    Returns:
        int: 0 on success, error code otherwise
    """
    setup_logging(arguments)

    # Check for requirements before importing modules that need them
    requirements.check_all()
    from PyIA import cli, connection

    interface = cli.CLI(arguments)
    connected = connection.update(interface.config)
    return not connected

def setup_logging(arguments: list[str]):
    """Set the log level depending on arguments, env vars, and the config file

    Args:
        arguments (list[str]): Raw CLI arguments
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-c", "--config")
    parser.add_argument("-L", "--log-level")

    parsed = vars(parser.parse_known_args(arguments)[0])

    if parsed["log_level"]:
        level = parsed["log_level"]
    else:
        try:
            import yaml

            with open(parsed["config"]) as config_file:
                level = yaml.safe_load(config_file)["log_level"]
        except (ImportError, FileNotFoundError, TypeError, KeyError):
            level = "info"

    logging.basicConfig(level=level.upper(), stream=sys.stdout)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
