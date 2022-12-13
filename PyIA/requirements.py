"""Functions check for runtime requiremntes"""

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
import os
import pathlib
import subprocess
import sys
import pkg_resources

logger = logging.getLogger(__name__)


def check_all() -> None:
    """Check for all the requirements and exit if they are not met"""
    if not _check_python_requirements():
        sys.exit(1)
    if not _check_root():
        sys.exit(2)
    if not _check_wireguard():
        sys.exit(3)
    logger.debug("all requirements met")
    return


def _check_root() -> bool:
    """Check if the script is being run by the root user.

    Returns:
        bool: True if the script is being run as root (effective user id == 0)
    """
    root = os.geteuid() == 0
    if not root:
        logger.error("not running as root")
    logger.debug("running as root")
    return root


def _check_python_requirements() -> bool:
    """Check to make sure the Python requiments are installed

    Returns:
        bool: True if the packages in requirements.txt are installed
    """
    packages_ok = True
    with open(pathlib.Path(__file__).parent.with_name("requirements.txt")) as reqs:
        dependencies = reqs.readlines()

    for package in [p.strip() for p in dependencies if p]:
        try:
            package = str(package)
            pkg_resources.require(package)
        except pkg_resources.DistributionNotFound:
            logger.error(f"missing required package '{package}'")
            packages_ok = False
        except pkg_resources.VersionConflict:
            logger.error(f"version conflict for package '{package}'")
            packages_ok = False
        else:
            logger.debug(f"requirement '{package}' is met")
    return packages_ok


def _check_wireguard() -> bool:
    """Check to see that wireguard and wg-quick are installed and working.

    Returns:
        bool: Wiregaurd and wg-quick present and OK
    """
    wireguard_ok = True
    for dependency in ["wg", "wg-quick"]:
        try:
            subprocess.check_call(
                [dependency, "-h"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError:
            logger.error(f"'{dependency}' isn't present or working right")
            wireguard_ok = False
            continue
        logger.debug(f"'{dependency}' is present")
    return wireguard_ok
