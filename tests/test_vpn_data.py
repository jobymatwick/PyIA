#!/usr/bin/env python3

"""Tests for VPN data classes"""

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

import os
import pytest

import PyIA.vpn_data as vpn_data


def test_hostValidIp():
    host = vpn_data.Host("hostname", "1.2.3.4")
    assert host.hostname == "hostname"
    assert host.ip == "1.2.3.4"


def test_hostInvalidIp():
    with pytest.raises(ValueError):
        vpn_data.Host("hostname", "bad.ip")


def test_saveAndLoadData():
    create = vpn_data.PersistentData(username="uname")
    vpn_data.save(create, "test.yml")
    data = vpn_data.load("test.yml")
    os.remove("test.yml")
    assert data.username == "uname"


def test_saveBadData():
    data = "Not PersistentData"
    with pytest.raises(TypeError):
        vpn_data.save(data, "test.yml")
    assert not os.path.exists("test.yml")
