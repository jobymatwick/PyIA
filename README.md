# PyIA (Pyvate Internet Access)
[![Test Status](https://github.com/jobymatwick/PyIA/actions/workflows/pytest.yaml/badge.svg?branch=main)](https://github.com/jobymatwick/PyIA/actions/workflows/pytest.yaml?branch=main)
[![Coverage Status](https://coveralls.io/repos/github/jobymatwick/PyIA/badge.svg?branch=main)](https://coveralls.io/github/jobymatwick/PyIA?branch=main)


Python application for establishing and maintaining Private Internet Access
Wireguard VPN connections. Fully idempotent so that it can be run by a timer or
cron job, ensuring that the host remains connected over time. Roughly based on
the steps outlined in the official
[manual-connections](https://github.com/pia-foss/manual-connections) shell
scripts.

**NOTE:** This project is under active development - Expect major changes.


## Installation
The general installation steps for a Debian-based system are included below.
Other distros will likely require similar steps.

### Requirements
- `python3`
- `python3-venv`
- `python3-pip`
- `git`
- `wg-quick` (from `wireguard` package)
- On Debian-based systems you may need to run `sudo sudo ln -s /usr/bin/resolvectl
  /usr/local/bin/resolvconf` for `wg-quick` to work properly

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

3. Copy the config template and update with with your information:
```bash
sudo cp config-template.yml config.yml
sudo chmod 600 config.yml
sudo nano config.yml
```

4. Install and enable the systemd units:
```bash
sudo cp systemd/* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start pyia.service
sudo systemctl start pyia.timer
sudo systemctl enable pyia.timer
```

5. Check to see that the oneshot unit ran successfully:
```bash
sudo systemctl status pyia.service
```

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

| Option Name            | Description                                                      | Default | Required |
|------------------------|------------------------------------------------------------------|---------|----------|
| `username`             | PIA username                                                     | None    | True     |
| `password`             | PIA password                                                     | None    | True     |
| `region`               | Server region (View options with `pyia.py -l`)                   | None    | True     |
| `port_forward`         | Enable port forwarding for the VPN connection                    | False   | False    |
| `port_forward_command` | Command to run if the forwarded port changes                     | None    | False    |
| `log_level`            | Application log level (critical, error, warning, info, or debug) | `info`  | False    |
