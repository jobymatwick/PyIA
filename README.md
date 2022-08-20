# PyIA (Pyvate Internet Access)
Python application for establishing and maintaining Private Internet Access
Wireguard VPN connections. Fully idempotent so that it can be run by a timer or
cron job, ensuring that the host remains connected over time. Roughly based on
the steps outlined in the official
[manual-connections](https://github.com/pia-foss/manual-connections) shell
scripts.

**NOTE:** This project is under active development and is not currently stable.
Expect major changes.

## Requirements
- `python3` and `python3-venv`
- `git`
- `wg-quick` (from `wireguard` package)
- `ping`

## Installation
1. Clone this repo:
```bash
sudo git clone https://github.com/jobymatwick/PyIA.git /opt/PyIA
cd /opt/PyIA
```

2. Create a Python venv and install dependencies:
```bash
sudo python3 -m venv .
sudo ./bin/pip3 install -r requirements.txt
```

**TODO:** Add additional instructions
