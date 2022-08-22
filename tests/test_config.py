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
from unittest import mock
import yaml

from PyIA import PiaApi
from PyIA import config

TEST_CONF = {
    "username": "user",
    "password": "pass",
    "region": "reg",
    "port_forward": True,
    "port_forward_command": "cmd",
    "log_level": "warn",
}


def mock_regions(arg):
    return {"testid": {"name": "testname", "port_forward": True}, "expiry_time": 0}


def test_allConf():
    with open("testconfig.yml", "w+") as conf_file:
        yaml.dump(TEST_CONF, conf_file)
    conf = config("-c testconfig.yml".split(" "))
    os.remove("testconfig.yml")
    assert conf == TEST_CONF


def test_allEnv():
    for key in TEST_CONF.keys():
        os.environ["PYIA_" + key.upper()] = str(TEST_CONF[key])
    conf = config([])
    assert conf == TEST_CONF


def test_allArgs():
    conf = config("-u user -p pass -r reg -P -q cmd -L warn".split(" "))
    assert conf == TEST_CONF


def test_listRegions(capfd):
    with pytest.raises(SystemExit) as e:
        with mock.patch.object(PiaApi, "regions", mock_regions):
            config(["-l"])
    out = capfd.readouterr()
    assert e.value.code == 0
    assert "Listing all regions" in out[0]
    assert "* testid" in out[0]


def test_EnvOverrideConf():
    with open("testconfig.yml", "w+") as conf_file:
        yaml.dump({"username": "toBeOverriden"}, conf_file)
    for key in TEST_CONF.keys():
        os.environ["PYIA_" + key.upper()] = str(TEST_CONF[key])
    conf = config("-c testconfig.yml".split(" "))
    os.remove("testconfig.yml")
    assert conf == TEST_CONF


def test_ArgsOverrideEnv():
    os.environ["PYIA_USERNAME"] = "toBeOverriden"
    conf = config("-u user -p pass -r reg -P -q cmd -L warn".split(" "))
    assert conf == TEST_CONF


def test_ArgsOverrideConf():
    with open("testconfig.yml", "w+") as conf_file:
        yaml.dump({"username": "toBeOverriden"}, conf_file)
    conf = config("-u user -p pass -r reg -P -q cmd -L warn".split(" "))
    os.remove("testconfig.yml")
    assert conf == TEST_CONF


def test_missingConfigAlert(capfd):
    with pytest.raises(SystemExit) as e:
        with mock.patch.object(PiaApi, "regions", mock_regions):
            config("-c missingconfig.yml".split(" "))
    out = capfd.readouterr()
    assert e.value.code != 0
