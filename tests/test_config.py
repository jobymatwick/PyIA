#!/usr/bin/env python3

"""Tests for the config generator"""

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
from pytest_mock import MockFixture as MockPytest
import yaml

from PyIA import config
from PyIA import vpn_data

TEST_CONF_DICT = {
    "username": "user",
    "password": "pass",
    "region": "reg",
    "port_forward": True,
    "port_forward_command": "cmd",
    "log_level": "warn",
}
TEST_PARSED_ARGS = {k.replace("_", "-"): v for k, v in TEST_CONF_DICT.items()}
TEST_CONF = config.Config(TEST_PARSED_ARGS)


def test_missingParameter():
    with pytest.raises(ValueError):
        config.Config({})


def test_allConf():
    with open("testconfig.yml", "w+") as conf_file:
        yaml.dump(TEST_CONF_DICT, conf_file)
    conf = config.Config({"config": "testconfig.yml"})
    os.remove("testconfig.yml")
    assert conf == TEST_CONF


def test_allEnv():
    for key in TEST_CONF_DICT.keys():
        os.environ["PYIA_" + key.upper()] = str(TEST_CONF_DICT[key])
    conf = config.Config([])
    assert conf == TEST_CONF


def test_allArgs():
    conf = config.Config(TEST_PARSED_ARGS)
    assert conf == TEST_CONF


# def mock_regions(arg):
#     return [vpn_data.Region("testid", "name", True, [])]

# def test_listRegions(capfd, mocker: MockPytest):
#     mocker.patch("PyIA.pia_api.PiaApi.regions", mock_regions)
#     with pytest.raises(SystemExit) as e:
#         config.Config({"list-regions": True})
#     out = capfd.readouterr()
#     assert e.value.code == 0
#     assert "Listing all regions" in out[0]
#     assert "* testid" in out[0]


# def test_showStatus(capfd, mocker: MockPytest):
#     mocker.patch("PyIA.wireguard.checkConfig", return_value=True)
#     mocker.patch("PyIA.wireguard.checkInterface", return_value=False)

#     with pytest.raises(SystemExit) as e:
#         config(["-s"])
#     out = capfd.readouterr()
#     assert e.value.code == 0
#     assert "config:         present" in out[0]
#     assert "interface:      down" in out[0]
#     assert "last refresh:   never"
#     assert "last handshake: N/A"


def test_EnvOverrideConf():
    with open("testconfig.yml", "w+") as conf_file:
        yaml.dump({"username": "toBeOverriden"}, conf_file)
    for key in TEST_CONF_DICT.keys():
        os.environ["PYIA_" + key.upper()] = str(TEST_CONF_DICT[key])
    conf = config.Config({"config": "testconfig.yml"})
    os.remove("testconfig.yml")
    assert conf == TEST_CONF


def test_ArgsOverrideEnv():
    os.environ["PYIA_USERNAME"] = "toBeOverriden"
    conf = config.Config(TEST_PARSED_ARGS)
    assert conf == TEST_CONF


def test_ArgsOverrideConf():
    with open("testconfig.yml", "w+") as conf_file:
        yaml.dump({"username": "toBeOverriden"}, conf_file)
    conf = config.Config(TEST_PARSED_ARGS)
    os.remove("testconfig.yml")
    assert conf == TEST_CONF
