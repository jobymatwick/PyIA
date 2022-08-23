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

import logging
import sys

from PyIA import config
from PyIA import updateConnection

if __name__ == "__main__":
    conf = config(sys.argv[1:])
    logging.basicConfig(level=conf['log_level'].upper(), stream=sys.stdout)
    connected = updateConnection(conf)
    sys.exit(0 if connected else 1)
