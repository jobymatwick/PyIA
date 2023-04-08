"""Combines config options from the CLI, environment vars, and config file"""

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
from typing import Any
import yaml
from dataclasses import dataclass, fields

FALSY_STRINGS = ["false", "f", "no", "0"]


@dataclass
class Config:
    """Application config dataclass

    Raises:
        ValueError: required config parameter was not provided
    """

    username: str = None
    password: str = None
    region: str = None
    port_forward: bool = False
    port_forward_command: str = ""

    def __init__(self, arguments: dict[str, Any]):
        """Generate a config object from parsed CLI arguments

        Args:
            arguments (dict[str, Any]): Parsed CLI arguments
        """
        if "config" in arguments and arguments["config"]:
            self.load_file(arguments["config"])
        self.load_env()
        self.load_flags(arguments)

        for parameter in fields(Config):
            if getattr(self, parameter.name) == None:
                raise ValueError(
                    f"Required config parameter {parameter.name} was never specified"
                )

    def load_file(self, config_filename: str) -> None:
        """Update config parameters with valuus from config yaml file

        Args:
            config_filename (str): Path of config file to load
        """
        with open(config_filename, "r") as config_file:
            config = yaml.safe_load(config_file)

        for parameter in fields(Config):
            if parameter.name in config:
                setattr(self, parameter.name, config[parameter.name])

    def load_env(self) -> None:
        """Update config parameters with valuus from environment variables"""
        for parameter in fields(Config):
            if f"PYIA_{parameter.name.upper()}" in os.environ:
                value = os.environ[f"PYIA_{parameter.name.upper()}"]
                if parameter.type == bool:
                    value = not (value in FALSY_STRINGS)
                setattr(self, parameter.name, value)

    def load_flags(self, arguments: dict[str, Any]) -> None:
        """Update config parameters with values from CLI arguments

        Args:
            arguments (dict[str, any]): Parsed CLI arguments
        """
        for parameter in fields(Config):
            name = parameter.name.replace("_", "-")
            if name in arguments and arguments[name] != None:
                setattr(
                    self, parameter.name, arguments[name]
                )
