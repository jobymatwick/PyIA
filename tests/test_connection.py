#!/usr/bin/env python3

"""Tests for the VPN connection manager"""

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

from pytest_mock import MockFixture as MockPytest

from PyIA import connection, pia_api
from .test_config import TEST_CONF
from .test_wireguard import TEST_CONN_INFO

TEST_PAIR = {"pubkey": "pubkey", "prikey": "prikey"}


class MockPiaApi:
    def __init__(self, fails: int):
        self.fails = fails

    def authenticate(self, *args):
        if self.fails:
            self.fails = self.fails - 1
            raise pia_api.ApiException("Failed for test")
        return TEST_CONN_INFO

    def portForward(self, command: str):
        assert command == TEST_CONF.port_forward_command

    def storeSuccess(self):
        pass


def test_newConnectionOk(mocker: MockPytest):
    mocks: list[MockPytest] = []
    mocks.append(mocker.patch("PyIA.pia_api.PiaApi", return_value=MockPiaApi(0)))
    mocks.append(mocker.patch("PyIA.wireguard.checkInterface", return_value=False))
    mocks.append(mocker.patch("PyIA.wireguard.createKeypair", return_value=TEST_PAIR))
    mocks.append(mocker.patch("PyIA.wireguard.createConfig"))
    mocks.append(mocker.patch("PyIA.wireguard.connect"))
    mocks.append(mocker.patch("PyIA.wireguard.checkConnection", return_value=True))

    status = connection.update(TEST_CONF)
    assert status == True
    for mock in mocks:
        assert mock.call_count == 1


def test_existingConnectionOk(mocker: MockPytest):
    mocks: list[MockPytest] = []
    mocks.append(mocker.patch("PyIA.pia_api.PiaApi", return_value=MockPiaApi(0)))
    mocks.append(mocker.patch("PyIA.wireguard.checkInterface", return_value=True))
    mocks.append(mocker.patch("PyIA.wireguard.checkConnection", return_value=True))

    status = connection.update(TEST_CONF)
    assert status == True
    for mock in mocks:
        assert mock.call_count == 1


def test_retriesAuthFails(mocker: MockPytest):
    mocker.patch("PyIA.pia_api.PiaApi", return_value=MockPiaApi(3))
    mocks: list[MockPytest] = []
    mocks.append(mocker.patch("PyIA.wireguard.checkInterface", return_value=False))
    mocks.append(mocker.patch("PyIA.wireguard.createKeypair", return_value=TEST_PAIR))

    status = connection.update(TEST_CONF)
    assert status == False
    for mock in mocks:
        assert mock.call_count == 3


def test_retriesConnectionFails(mocker: MockPytest):
    mocker.patch("PyIA.pia_api.PiaApi", return_value=MockPiaApi(0))
    mocks: list[MockPytest] = []
    mocks.append(mocker.patch("PyIA.wireguard.checkInterface", return_value=False))
    mocks.append(mocker.patch("PyIA.wireguard.createKeypair", return_value=TEST_PAIR))
    mocks.append(mocker.patch("PyIA.wireguard.createConfig", return_value=None))
    mocks.append(mocker.patch("PyIA.wireguard.connect", return_value=False))
    mocks.append(mocker.patch("PyIA.wireguard.checkConnection", return_value=False))
    mocks.append(mocker.patch("PyIA.wireguard.removeConfig", return_value=None))

    status = connection.update(TEST_CONF)
    assert status == False
    for mock in mocks:
        assert mock.call_count == 3
