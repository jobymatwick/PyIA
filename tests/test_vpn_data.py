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

import base64
import datetime
import json
import os
import time
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


def test_tokenExpired():
    data = vpn_data.PersistentData(token_expiry=time.time() - 1, token="token")
    assert not data.tokenValid()


def test_tokenMissing():
    data = vpn_data.PersistentData(token_expiry=time.time() + 1)
    assert not data.tokenValid()


def test_tokenValid():
    data = vpn_data.PersistentData(token_expiry=time.time() + 1, token="token")
    assert data.tokenValid()


def test_regionsExpired():
    data = vpn_data.PersistentData(regions_expiry=time.time() - 1, regions=["regions"])
    assert not data.regionsValid()


def test_regionsMissing():
    data = vpn_data.PersistentData(regions_expiry=time.time() + 1)
    assert not data.regionsValid()


def test_regionsValid():
    data = vpn_data.PersistentData(regions_expiry=time.time() + 1, regions=["regions"])
    assert data.regionsValid()


def test_payloadMissing():
    data = vpn_data.PersistentData(signature="sig")
    assert not data.payloadValid()


def test_signatureMissing():
    data = vpn_data.PersistentData(payload="pay")
    assert not data.payloadValid()


def test_payloadExpired():
    data = vpn_data.PersistentData(
        signature="sig",
        payload=base64.b64encode(
            json.dumps(
                {"signature": "sig", "expires_at": "2000-01-01T01:01:01.000000000Z"}
            ).encode()
        ).decode("utf-8"),
    )
    assert not data.payloadValid()


def test_payloadBadSig():
    data = vpn_data.PersistentData(
        signature="sig",
        payload=base64.b64encode(
            json.dumps(
                {
                    "signature": "badsig",
                    "expires_at": (
                        datetime.datetime.now() + datetime.timedelta(0, 60)
                    ).isoformat()
                    + "000Z",
                }
            ).encode()
        ).decode("utf-8"),
    )
    assert not data.payloadValid()


def test_payloadValid():
    data = vpn_data.PersistentData(
        signature="sig",
        payload=base64.b64encode(
            json.dumps(
                {
                    "signature": "sig",
                    "expires_at": (
                        datetime.datetime.now() + datetime.timedelta(0, 60)
                    ).isoformat()
                    + "000Z",
                }
            ).encode()
        ).decode("utf-8"),
    )
    assert data.payloadValid()


def test_portInvalid():
    data = vpn_data.PersistentData(signature="sig")
    assert data.portFromPayload() == 0


def test_portValid():
    data = vpn_data.PersistentData(
        signature="sig",
        payload=base64.b64encode(
            json.dumps(
                {
                    "signature": "sig",
                    "expires_at": (
                        datetime.datetime.now() + datetime.timedelta(0, 60)
                    ).isoformat()
                    + "000Z",
                    "port": 12345,
                }
            ).encode()
        ).decode("utf-8"),
    )
    assert data.portFromPayload() == 12345
