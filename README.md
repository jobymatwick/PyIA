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

## Configuration
Configuration options can be set via CLI flags, environment variables, and a
config file. Options set via CLI flags override all others, and environment
variables override the config file.

While there are command line flags for the PIA username and password, it is
recommended that these be set via environment variables or a config file with
proper permissions (ie. `chmod 600 config.yml`). This so that your credentials
are not visible in the list of processes while the application runs.

Environment variables names are composed of the option name below in all
capitals prepended by `PYIA_`. For example, to set the username option, the
variable `PYIA_USERNAME` must be set.

| Option Name            | Description                                                   | Default | Required |
|------------------------|---------------------------------------------------------------|---------|----------|
| `username`             | PIA username                                                  | None    | True     |
| `password`             | PIA password                                                  | None    | True     |
| `region`               | Server region (View options with `PyIA -l`)                   | None    | True     |
| `port_forward`         | Enable port forwarding for the VPN connection                 | False   | False    |
| `port_forward_command` | Command to run if the forwarded port changes                  | None    | False    |
| `log_level`            | Application log level (critical, error, warning, info, debug) | `info`  | False    |
