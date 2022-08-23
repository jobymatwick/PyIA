#!/usr/bin/env python3

"""Tests for the PIA API interface class PiaApi"""

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
from requests_mock.mocker import Mocker
import time

from PyIA import PiaApi

SAMPLE_REGIONS = {
    "regions": [
        {
            "id": f"testid{i}",
            "name": f"testname{i}",
            "port_forward": True,
            "servers": {
                "wg": [{"ip": f"{j}.{j}.{j}.{j}", "cn": f"host{j}"} for j in range(3)]
            }
            if i != 1
            else {},
        }
        for i in range(100)
    ]
}


class TestPiaApi:
    def setup_method(self):
        self.api = PiaApi("username", "password", "test.json")

    def teardown_method(self):
        if os.path.exists("test.json"):
            os.remove("test.json")

    def test_classCreatesBlankDataFile(self):
        assert os.path.exists("test.json")
        with open("test.json") as f:
            assert f.read() == "{}\n"

    def test_checksTokenResp(self, requests_mock: Mocker):
        requests_mock.get(
            self.api.TOKEN_ADDRESS,
            json={"status": "ERROR", "message": "error message"},
        )
        with pytest.raises(RuntimeError):
            self.api.token()

    def test_returnsNewToken(self, requests_mock: Mocker):
        requests_mock.get(
            self.api.TOKEN_ADDRESS,
            json={"status": "OK", "token": "testtoken"},
        )
        token_time = time.time()
        token = self.api.token()
        assert token == "testtoken"

    def test_savesNewToken(self, requests_mock: Mocker):
        requests_mock.get(
            self.api.TOKEN_ADDRESS,
            json={"status": "OK", "token": "testtoken"},
        )
        token_time = time.time()
        self.api.token()
        assert self.api._loadData()["token"]["key"] == "testtoken"

    def test_savesNewTokenUser(self, requests_mock: Mocker):
        requests_mock.get(
            self.api.TOKEN_ADDRESS,
            json={"status": "OK", "token": "testtoken"},
        )
        self.api.token()
        assert self.api._loadData()["token"]["user"] == "username"

    def test_savesNewTokenExpiry(self, requests_mock: Mocker):
        requests_mock.get(
            self.api.TOKEN_ADDRESS,
            json={"status": "OK", "token": "testtoken"},
        )
        token_time = time.time()
        self.api.token()
        assert int(self.api._loadData()["token"]["expiry_time"]) == int(
            token_time + self.api.TOKEN_LIFE_SECONDS
        )

    def test_storedTokenOk(self):
        self.api._saveData(
            {
                "token": {
                    "user": "username",
                    "expiry_time": time.time() + 1,
                    "key": "key",
                }
            }
        )
        assert self.api.token() == "key"

    def test_storedTokenMissing(self):
        assert self.api._getStoredToken() == ""

    def test_storedTokenWrongUser(self):
        self.api._saveData({"token": {"user": "wrong"}})
        assert self.api._getStoredToken() == ""

    def test_storedTokenExpired(self):
        t = time.time() - 1
        self.api._saveData({"token": {"user": "username", "expiry_time": t}})
        assert self.api._getStoredToken() == ""

    def test_checksRegionResp(self, requests_mock: Mocker):
        requests_mock.get(self.api.REGION_ADDRESS, status_code=403)
        with pytest.raises(RuntimeError):
            self.api.regions()

    def test_checksRegionRespLen(self, requests_mock: Mocker):
        requests_mock.get(self.api.REGION_ADDRESS, text="abc123")
        with pytest.raises(ValueError):
            self.api.regions()

    def test_returnsNewRegions(self, requests_mock: Mocker):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        regions = self.api.regions()
        assert len(regions) == len(SAMPLE_REGIONS["regions"])

    def test_savesRegions(self, requests_mock: Mocker):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        regions = self.api.regions()
        assert self.api._loadData()["regions"]["testid0"]["name"] == "testname0"
        assert self.api._loadData()["regions"]["testid0"]["port_forward"] == True
        assert self.api._loadData()["regions"]["testid0"]["servers"] == [
            [f"host{j}", f"{j}.{j}.{j}.{j}"] for j in range(3)
        ]

    def test_savesNewRegionsExpiry(self, requests_mock: Mocker):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        region_time = time.time()
        self.api.regions()
        assert int(self.api._loadData()["regions"]["expiry_time"]) == int(
            region_time + self.api.REGION_LIFE_SECONDS
        )

    def test_storedRegionsOk(self):
        self.api._saveData(
            {"regions": {"region": "stored", "expiry_time": time.time() + 1}}
        )
        assert self.api.regions()["region"] == "stored"

    def test_storedRegionsMissing(self):
        assert self.api._getStoredRegions() == []

    def test_storedRegionsExpired(self):
        self.api._saveData(
            {"regions": {"region": "stored", "expiry_time": time.time() - 1}}
        )
        assert self.api._getStoredRegions() == []

    def test_downloadsCert(self, requests_mock: Mocker):
        with open("tests/test_cert.crt", "r") as test_cert:
            cert_text = test_cert.read()
        requests_mock.get(self.api.SSL_CERT_ADDRESS, text=cert_text)
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        open("ca.rsa.4096.crt", "a").close()
        os.remove("ca.rsa.4096.crt")
        try:
            self.api.authenticate("testid0", "")
        except Exception:
            pass
        assert os.path.exists("ca.rsa.4096.crt")

        with open("ca.rsa.4096.crt", "r") as cert_file:
            assert cert_file.read() == cert_text

    def test_authenticateInvalidRegion(self, requests_mock: Mocker):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        with pytest.raises(ValueError):
            self.api.authenticate("invalid", "")

    def test_checksAuthResp(self, requests_mock: Mocker):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        requests_mock.get(self.api.TOKEN_ADDRESS, json={"status": "OK", "token": ""})
        requests_mock.get(
            "https://0.0.0.0:1337/addKey",
            json={"status": "ERROR", "message": "error message"},
        )
        with pytest.raises(RuntimeError):
            self.api.authenticate("testid0", "")

    def test_returnsConnInfo(self, requests_mock: Mocker):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        requests_mock.get(self.api.TOKEN_ADDRESS, json={"status": "OK", "token": ""})
        requests_mock.get(
            "https://0.0.0.0:1337/addKey",
            json={
                "status": "OK",
                "peer_ip": "1.2.3.4",
                "dns_servers": ["8.8.8.8"],
                "server_key": "pubkey",
                "server_ip": "9.8.7.6",
                "server_port": "1337",
            },
        )
        conn_info = self.api.authenticate("testid0", "")
        assert conn_info == {
            "address": "1.2.3.4",
            "dns": "8.8.8.8",
            "pubkey": "pubkey",
            "host": "host0",
            "endpoint": "9.8.7.6:1337",
        }
