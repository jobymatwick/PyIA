"""Tests for the requirement checker"""

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

import subprocess
import pkg_resources
import pytest
from pytest_mock import MockFixture as MockPytest

from PyIA import requirements

CHECK_FNS = ["_check_python_requirements", "_check_root", "_check_wireguard"]


@pytest.mark.parametrize("euid, is_root", [(0, True), (1, False)])
def test_rootCheck(euid: int, is_root: bool, mocker: MockPytest):
    mocker.patch("os.geteuid", return_value=euid)
    assert requirements._check_root() == is_root


def test_packagesOk(mocker: MockPytest):
    mocker.patch("pkg_resources.require", return_value=True)
    assert requirements._check_python_requirements()


def test_packagesMissing(mocker: MockPytest):
    mocker.patch(
        "pkg_resources.require", side_effect=pkg_resources.DistributionNotFound
    )
    assert not requirements._check_python_requirements()


def test_packagesVersion(mocker: MockPytest):
    mocker.patch("pkg_resources.require", side_effect=pkg_resources.VersionConflict)
    assert not requirements._check_python_requirements()


def test_wireguardOk(mocker: MockPytest):
    mocker.patch("subprocess.check_call", return_value=True)
    assert requirements._check_wireguard()


def test_wireguardMissing(mocker: MockPytest):
    mocker.patch(
        "subprocess.check_call", side_effect=subprocess.CalledProcessError(1, "err")
    )
    assert not requirements._check_wireguard()


def test_checkAllRequirementsMet(mocker: MockPytest):
    for check_fn in CHECK_FNS:
        mocker.patch(f"PyIA.requirements.{check_fn}", return_value=True)
    requirements.check_all()


@pytest.mark.parametrize("failing_check", CHECK_FNS)
def test_checkAllRequirementsUnmet(failing_check: str, mocker: MockPytest):
    for check_fn in CHECK_FNS:
        check_passes = check_fn != failing_check
        mocker.patch(f"PyIA.requirements.{check_fn}", return_value=check_passes)
    with pytest.raises(SystemExit) as e:
        requirements.check_all()
    assert e.value.code == (CHECK_FNS.index(failing_check) + 1)
