#!/usr/bin/env python3

"""Tests for the Wireguard interface"""

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
from pytest_mock import MockFixture as MockPytest
from requests_mock.mocker import Mocker as MockRequest
import subprocess

from PyIA import wireguard

TEST_CONN_INFO = {
    "address": "1.2.3.4",
    "dns": "8.8.8.8",
    "pubkey": "pubkey",
    "host": "host0",
    "endpoint": "9.8.7.6:1337",
}

TEST_CONFIG = """[Interface]
Address = 1.2.3.4
PrivateKey = biglongprivatekey=
DNS = 8.8.8.8

[Peer]
PersistentKeepalive = 25
PublicKey = pubkey
AllowedIPs = 0.0.0.0/0
Endpoint = 9.8.7.6:1337
# Hostname = host0
"""


def test_generateKeypair(mocker: MockPytest):
    mock = mocker.patch(
        "subprocess.check_output",
        side_effect=[b"biglongprivatekey=", b"biglongpublickey="],
    )

    pair = wireguard.createKeypair()
    assert pair == {"pubkey": "biglongpublickey=", "prikey": "biglongprivatekey="}
    assert mock.call_args_list == [
        mocker.call(["wg", "genkey"]),
        mocker.call(["wg", "pubkey"], input=b"biglongprivatekey="),
    ]


def test_keyPairError(mocker: MockPytest, caplog):
    mock = mocker.patch(
        "subprocess.check_output", side_effect=subprocess.CalledProcessError(1, "")
    )

    pair = wireguard.createKeypair()
    assert pair == None
    assert "failed" in caplog.text.lower()


def test_configCreation(mocker: MockPytest):
    mocker.patch("PyIA.wireguard.WIREGUARD_DIR", "")

    wireguard.createConfig(TEST_CONN_INFO, "biglongprivatekey=")

    with open("pia.conf", "r") as f:
        config = f.read()
    os.remove("pia.conf")
    assert config == TEST_CONFIG


def test_connectionOk(requests_mock: MockRequest, mocker: MockPytest):
    requests_mock.get(
        wireguard.IP_CHECK_URL,
        content=TEST_CONN_INFO["endpoint"].split(":")[0].encode(),
    )
    mocker.patch("PyIA.wireguard.WIREGUARD_DIR", "")
    wireguard.createConfig(TEST_CONN_INFO, "biglongprivatekey=")

    status = wireguard.checkConnection()
    os.remove("pia.conf")
    assert status == True


def test_connectionRetries(requests_mock: MockRequest):
    mock = requests_mock.get(
        wireguard.IP_CHECK_URL,
        content=b"not an ip",
    )

    status = wireguard.checkConnection()
    assert mock.call_count == wireguard.IP_RETRIES
    assert status == False


def test_connectionMismatch(requests_mock: MockRequest, mocker: MockPytest):
    requests_mock.get(
        wireguard.IP_CHECK_URL,
        content=b"9.9.9.9",
    )
    mocker.patch("PyIA.wireguard.WIREGUARD_DIR", "")
    wireguard.createConfig(TEST_CONN_INFO, "biglongprivatekey=")

    status = wireguard.checkConnection()
    os.remove("pia.conf")
    assert status == False


def test_configPresent(mocker: MockPytest):
    mocker.patch("PyIA.wireguard.WIREGUARD_DIR", "")
    wireguard.createConfig(TEST_CONN_INFO, "biglongprivatekey=")

    status = wireguard.checkConfig()
    os.remove("pia.conf")
    assert status == True


def test_configAbsent():
    status = wireguard.checkConfig()
    assert status == False


def test_ifPresent(mocker: MockPytest):
    mocker.patch("PyIA.wireguard.NETWORK_IF_DIR", "./")
    open("pia", "a").close()

    status = wireguard.checkInterface()
    os.remove("pia")
    assert status == True


def test_ifAbsent(mocker: MockPytest):
    mocker.patch("PyIA.wireguard.NETWORK_IF_DIR", "./")
    assert wireguard.checkInterface() == False


def test_connectOk(mocker: MockPytest):
    mock = mocker.patch("subprocess.run")
    mock.return_value.returncode = 0

    status = wireguard.connect()
    assert status == True
    assert mock.call_args == mocker.call(["/usr/bin/wg-quick", "up", "pia"])


def test_connectErr(mocker: MockPytest):
    mock = mocker.patch("subprocess.run")
    mock.return_value.returncode = 1

    status = wireguard.connect()
    assert status == False