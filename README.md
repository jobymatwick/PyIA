# PyIA (Pyvate Internet Access)
[![Test Status](https://github.com/jobymatwick/PyIA/actions/workflows/pytest.yaml/badge.svg?branch=main)](https://github.com/jobymatwick/PyIA/actions/workflows/pytest.yaml?branch=main)
[![Coverage Status](https://coveralls.io/repos/github/jobymatwick/PyIA/badge.svg?branch=main)](https://coveralls.io/github/jobymatwick/PyIA?branch=main)


Python application for establishing and maintaining Private Internet Access
Wireguard VPN connections. Fully idempotent so that it can be run by a timer or
cron job, ensuring that the host remains connected over time. Roughly based on
the steps outlined in the official
[manual-connections](https://github.com/pia-foss/manual-connections) shell
scripts.

Features include:
* Automatic authentication with PIA servers
* Retries if connection fails
* Port-forwarding support
* Ability to run custom command when forwarded port changes
* Fully [idempotent](https://en.wikipedia.org/wiki/Idempotence)
* Lightweight (Nothing running between connection refreshes)

**NOTE:** This project is under active development - Expect major changes.

## Setup and Usage
Installation instructions are included in the wiki
[here](https://https://github.com/jobymatwick/PyIA/wiki/Setup). Configuration
and usage instructions can be found
[here](https://https://github.com/jobymatwick/PyIA/wiki/Configuration-and-Usage).
