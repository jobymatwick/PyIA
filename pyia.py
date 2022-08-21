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

import PyIA.config
import PyIA.pia_api
import PyIA.wireguard

if __name__ == "__main__":
    conf = PyIA.config.get()
    logging.basicConfig(level=conf['log_level'].upper(), stream=sys.stdout)

    if not PyIA.wireguard.checkConfig():
        token = PyIA.pia_api.getToken({'user': conf['username'], 'pass': conf['password']})
        region = PyIA.pia_api.getRegionInfo(conf['region'])
        keypair = PyIA.wireguard.createKeypair()
        conn_info = PyIA.pia_api.authenticate(region, token, keypair['pubkey'])
        PyIA.wireguard.createConfig(conn_info, keypair['prikey'])

    if not PyIA.wireguard.checkInterface():
        PyIA.wireguard.connect()

    PyIA.wireguard.checkConnection()
