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

import base64
import copy
import datetime
import json
import os
import pytest
from pytest_mock import MockFixture as MockPytest
from requests_mock.mocker import Mocker as MockRequest
import time

from PyIA import pia_api, vpn_data

TEST_FILE = "test_api.yml"
SAMPLE_REGIONS = {
    "regions": [
        {
            "id": f"testid{i}",
            "name": f"testname{i}",
            "port_forward": True,
            "servers": {
                "wg": [{"ip": f"{j}.{j}.{j}.{j}", "cn": f"host{j}"} for j in range(3)]
            },
        }
        for i in range(100)
    ]
}

AUTH_RESPONSE = {
    "status": "OK",
    "peer_ip": "1.2.3.4",
    "dns_servers": ["8.8.8.8"],
    "server_key": "pubkey",
    "server_ip": "9.8.7.6",
    "server_port": "1337",
}

SIGNATURE_RESPONSE = {
    "status": "OK",
    "signature": "sig",
    "payload": base64.b64encode(
        json.dumps(
            {
                "signature": "sig",
                "expires_at": (
                    datetime.datetime.utcnow() + datetime.timedelta(0, 600)
                ).isoformat()
                + "000Z",
                "port": 12345,
            }
        ).encode()
    ).decode("utf-8"),
}


class TestPiaApi:
    def setup_method(self):
        self.api = pia_api.PiaApi("username", "password", TEST_FILE)

    def teardown_method(self):
        if os.path.exists(TEST_FILE):
            os.remove(TEST_FILE)

    def test_checksTokenResp(self, requests_mock: MockRequest):
        requests_mock.get(
            self.api.TOKEN_ADDRESS,
            json={"status": "ERROR", "message": "error message"},
        )
        with pytest.raises(pia_api.ApiException):
            self.api.token()

    def test_returnsNewToken(self, requests_mock: MockRequest):
        requests_mock.get(
            self.api.TOKEN_ADDRESS,
            json={"status": "OK", "token": "testtoken"},
        )
        token = self.api.token()
        assert token == "testtoken"

    def test_savesNewToken(self, requests_mock: MockRequest):
        requests_mock.get(
            self.api.TOKEN_ADDRESS,
            json={"status": "OK", "token": "testtoken"},
        )
        self.api.token()
        token_time = int(time.time())
        loaded = vpn_data.load(TEST_FILE)
        assert loaded.token == "testtoken"
        assert loaded.username == "username"
        assert loaded.token_expiry == token_time + self.api.TOKEN_LIFE_SECONDS

    def test_storedTokenOk(self):
        vpn_data.save(
            vpn_data.PersistentData(token="key", token_expiry=int(time.time() + 1)),
            TEST_FILE,
        )
        self.api.data = vpn_data.load(TEST_FILE)
        assert self.api.token() == "key"

    def test_fileIfUsernameMatch(self, requests_mock: MockRequest):
        self.test_returnsNewToken(requests_mock)
        api = pia_api.PiaApi("username", "password", TEST_FILE)
        assert api.data.token == "testtoken"

    def test_fileIfUsernameMismatch(self, requests_mock: MockRequest):
        self.test_returnsNewToken(requests_mock)
        api = pia_api.PiaApi("othername", "password", TEST_FILE)
        assert api.data.token == None

    def test_checksRegionResp(self, requests_mock: MockRequest):
        requests_mock.get(self.api.REGION_ADDRESS, status_code=403)
        with pytest.raises(pia_api.ApiException):
            self.api.regions()

    def test_checksRegionRespLen(self, requests_mock: MockRequest):
        requests_mock.get(self.api.REGION_ADDRESS, text="abc123")
        with pytest.raises(pia_api.ApiException):
            self.api.regions()

    def test_returnsNewRegions(self, requests_mock: MockRequest):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        regions = self.api.regions()
        assert len(regions) == len(SAMPLE_REGIONS["regions"])

    def test_omitsNonWgRegion(self, requests_mock: MockRequest):
        regions = copy.deepcopy(SAMPLE_REGIONS)
        regions["regions"][1]["servers"].pop("wg")
        requests_mock.get(self.api.REGION_ADDRESS, json=regions)
        regions = self.api.regions()
        assert len(regions) == len(SAMPLE_REGIONS["regions"]) - 1

    def test_downloadsCert(self, requests_mock: MockRequest):
        with open("tests/test_cert.crt", "r") as test_cert:
            cert_text = test_cert.read()
        requests_mock.get(self.api.SSL_CERT_ADDRESS, text=cert_text)
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        open("ca.rsa.4096.crt", "a").close()
        os.remove("ca.rsa.4096.crt")
        try:
            self.api._sslGet(0, "", {})
        except Exception:
            pass
        assert os.path.exists("ca.rsa.4096.crt")

        with open("ca.rsa.4096.crt", "r") as cert_file:
            assert cert_file.read() == cert_text

    def test_authInvalidRegion(self, requests_mock: MockRequest):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        with pytest.raises(ValueError):
            self.api.authenticate("invalid", "")

    def test_checksAuthResp(self, requests_mock: MockRequest):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        requests_mock.get(self.api.TOKEN_ADDRESS, json={"status": "OK", "token": ""})
        requests_mock.get(
            "https://0.0.0.0:1337/addKey",
            json={"status": "ERROR", "message": "error message"},
        )
        with pytest.raises(pia_api.ApiException):
            self.api.authenticate("testid0", "")

    def test_authReturnsConnInfo(self, requests_mock: MockRequest):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        requests_mock.get(self.api.TOKEN_ADDRESS, json={"status": "OK", "token": ""})
        requests_mock.get("https://0.0.0.0:1337/addKey", json=AUTH_RESPONSE)
        conn_info = self.api.authenticate("testid0", "")
        assert conn_info == vpn_data.Connection(
            vpn_data.Host("host0", "0.0.0.0"), 1337, "1.2.3.4", "pubkey", ["8.8.8.8"]
        )

    def test_pfNoSavedNoCommand(self, requests_mock: MockRequest, mocker: MockPytest):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        requests_mock.get(self.api.TOKEN_ADDRESS, json={"status": "OK", "token": "key"})
        requests_mock.get("https://0.0.0.0:1337/addKey", json=AUTH_RESPONSE)
        requests_mock.get("https://0.0.0.0:19999/getSignature", json=SIGNATURE_RESPONSE)
        requests_mock.get("https://0.0.0.0:19999/bindPort", json={"status": "OK"})
        mock = mocker.patch("subprocess.run")
        self.api.authenticate("testid0", "")
        self.api.portForward()
        loaded = vpn_data.load(TEST_FILE)
        assert loaded.portFromPayload() == 12345
        assert mock.call_count == 0

    def test_pfNoSavedCommand(self, requests_mock: MockRequest, mocker: MockPytest):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        requests_mock.get(self.api.TOKEN_ADDRESS, json={"status": "OK", "token": "key"})
        requests_mock.get("https://0.0.0.0:1337/addKey", json=AUTH_RESPONSE)
        requests_mock.get("https://0.0.0.0:19999/getSignature", json=SIGNATURE_RESPONSE)
        requests_mock.get("https://0.0.0.0:19999/bindPort", json={"status": "OK"})
        mock = mocker.patch("subprocess.run")
        mock.return_value.returncode = 0
        self.api.authenticate("testid0", "")
        self.api.portForward("cmd " + self.api.PORT_TEMPLATE)

        assert mock.call_count == 1
        assert mock.call_args.args[0] == ["cmd", "12345"]

    def test_pfSaved(self, requests_mock: MockRequest, mocker: MockPytest):
        self.test_pfNoSavedNoCommand(requests_mock, mocker)
        mock = requests_mock.get(
            "https://0.0.0.0:19999/bindPort", json={"status": "OK"}
        )
        subp = mocker.patch("subprocess.run")
        self.api.portForward("cmd")
        assert mock.call_count == 1
        assert subp.call_count == 0

    def test_pfNoSavedSigFail(self, requests_mock: MockRequest):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        requests_mock.get(self.api.TOKEN_ADDRESS, json={"status": "OK", "token": "key"})
        requests_mock.get("https://0.0.0.0:1337/addKey", json=AUTH_RESPONSE)
        requests_mock.get(
            "https://0.0.0.0:19999/getSignature", json={"status": "err", "message": ""}
        )
        self.api.authenticate("testid0", "")
        with pytest.raises(pia_api.ApiException):
            self.api.portForward()

    def test_pfNoSavedSigInvalid(self, requests_mock: MockRequest):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        requests_mock.get(self.api.TOKEN_ADDRESS, json={"status": "OK", "token": "key"})
        requests_mock.get("https://0.0.0.0:1337/addKey", json=AUTH_RESPONSE)
        requests_mock.get(
            "https://0.0.0.0:19999/getSignature",
            json={"status": "OK", "signature": "sig", "payload": "no"},
        )
        self.api.authenticate("testid0", "")
        with pytest.raises(pia_api.ApiException):
            self.api.portForward()

    def test_pfBindExpiredRetry(self, requests_mock: MockRequest):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        requests_mock.get(self.api.TOKEN_ADDRESS, json={"status": "OK", "token": "key"})
        requests_mock.get("https://0.0.0.0:1337/addKey", json=AUTH_RESPONSE)
        mock = requests_mock.get(
            "https://0.0.0.0:19999/getSignature", json=SIGNATURE_RESPONSE
        )
        requests_mock.get(
            "https://0.0.0.0:19999/bindPort",
            [
                {
                    "json": {"status": "error", "message": "port expired"},
                    "status_code": 400,
                },
                {
                    "json": {"status": "OK", "message": "bind success"},
                    "status_code": 200,
                },
            ],
        )
        self.api.authenticate("testid0", "")
        self.api.portForward()
        assert mock.call_count == 2

    def test_pfBindFail(self, requests_mock: MockRequest):
        requests_mock.get(self.api.REGION_ADDRESS, json=SAMPLE_REGIONS)
        requests_mock.get(self.api.TOKEN_ADDRESS, json={"status": "OK", "token": "key"})
        requests_mock.get("https://0.0.0.0:1337/addKey", json=AUTH_RESPONSE)
        requests_mock.get("https://0.0.0.0:19999/getSignature", json=SIGNATURE_RESPONSE)
        requests_mock.get(
            "https://0.0.0.0:19999/bindPort", json={"status": "error", "message": ""}
        )
        self.api.authenticate("testid0", "")
        with pytest.raises(pia_api.ApiException):
            self.api.portForward()

    def test_storeSuccess(self):
        self.api.storeSuccess()
        assert self.api.data.last_success == int(time.time())
