"""CLI sub-utilities"""

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
import time
import sys

from . import wireguard, pia_api, config


class CLI:
    """Command line application interface. Parses arguments and runs utilities."""

    def __init__(self, args: list[str]) -> None:
        """Process command line arguments, run utilities as required, and
        generate a config object.

        Args:
            args (list[str]): Raw CLI arguments
        """
        parser = argparse.ArgumentParser(
            description="Python application for establishing and maintaining Private "
            "Internet Access Wireguard VPN connections."
        )

        parser.add_argument("-c", "--config", help="Config file to load")
        parser.add_argument("-u", "--username", help="PIA account username")
        parser.add_argument("-p", "--password", help="PIA account password")
        parser.add_argument("-r", "--region", help="ID of server region to connect to")
        parser.add_argument(
            "-P", "--port-forward", action="store_true", help="Forward port"
        )
        parser.add_argument(
            "-q", "--port-forward-command", help="Run when port changes"
        )
        parser.add_argument(
            "-L", "--log-level", help="Application output logging level"
        )
        parser.add_argument(
            "-s", "--status", action="store_true", help="Get connection status"
        )
        parser.add_argument(
            "-l", "--list-regions", action="store_true", help="List regions"
        )

        parsed = parser.parse_args(args[1:])
        self.config = config.Config(vars(parsed))
        # Run CLI utilities
        if parsed.status:
            self.status()
        elif parsed.list_regions:
            self.list_regions()

    def status(self) -> None:
        """Print the status of the VPN connection and exit."""
        config_present = wireguard.checkConfig()
        interface_state = wireguard.checkInterface()
        port = pia_api.PiaApi("", "").data.portFromPayload() if interface_state else 0
        r = pia_api.PiaApi("", "").data.last_success if interface_state else 0
        time_since_refresh = f"{((time.time() - r) / 60):.1f}m ago" if r else "never"
        info = (
            wireguard.getConnectionInfo()
            if interface_state
            else dict.fromkeys(wireguard.INFO_KEYS, "N/A")
        )

        print("PyIA Info:")
        print(f"  config:         {'pre' if config_present else 'ab'}sent")
        print(f"  interface:      {'up' if interface_state else 'down'}")
        print(f"  last refresh:   {time_since_refresh}\n")
        print("Wireguard Connection Info:")
        print(f"  last handshake: {info['handshake']}")
        print(f"  public ip:      {info['endpoint']}")
        print(f"  forwarded port: {port if port else 'N/A'}")
        print(f"  data transfer:  rx={info['rx']},tx={info['tx']}")
        sys.exit(0)

    def list_regions(self) -> None:
        """Download and print the current PIA server list."""
        regions = pia_api.PiaApi("", "").regions()
        print("Listing all regions. (*) means regions supports port forwarding.\n")
        print("  Region ID             Region Name")
        print("---------------------------------------------")
        for region in regions:
            print(f'{"*" if region.port_forward else " "} {region.id:22}{region.name}')
        sys.exit(0)
