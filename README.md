# Akamai Network List Manager

[![CI](https://github.com/AtakanUk/akamai-network-list-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/AtakanUk/akamai-network-list-manager/actions/workflows/ci.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Command-line tool for Akamai Network Lists, the IP/CIDR block lists used by Akamai WAF and App & API Protector policies. Blocking an attacker at the edge is a single SOAR playbook step:

```bash
python akamai_network_list_manager.py block --items 198.51.100.23,203.0.113.0/24 --activate PRODUCTION
```

## Features

- `block` / `unblock` IPs and CIDRs (IPv4 and IPv6). Input is validated and normalised (`192.0.2.9/24` → `192.0.2.0/24`), and duplicates are dropped before anything is sent.
- Optional activation right after the change (`--activate [STAGING|PRODUCTION]`), with an automatic comment that lists the touched addresses.
- `activate` and `status` to push a list and follow its activation.
- `list-all`, `get`, `client-lists` for inspection.
- EdgeGrid authentication, with `accountSwitchKey` support for partner / multi-account API clients.
- Every request and response status is logged, which gives an audit trail of what changed at the edge.

## Requirements

- Python 3.11+
- An Akamai API client with read-write access to the Network Lists API (`/network-list/v2`)

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `AKAMAI_HOST` | Yes | API host of the client (`akab-….luna.akamaiapis.net`) |
| `AKAMAI_CLIENT_TOKEN`, `AKAMAI_CLIENT_SECRET`, `AKAMAI_ACCESS_TOKEN` | Yes | EdgeGrid credentials |
| `AKAMAI_ACCOUNT_SWITCH_KEY` | No | Account switch key for multi-account clients |
| `AKAMAI_NETWORK_LIST_ID` | No | Default list when `--list-id` is omitted |
| `AKAMAI_ENVIRONMENT` | No | Default activation environment (`STAGING`) |

## Usage

```bash
pip install -r requirements.txt

python akamai_network_list_manager.py list-all
python akamai_network_list_manager.py get --list-id 12345_SOCBLOCKLIST
python akamai_network_list_manager.py block --items 198.51.100.23 --activate          # default environment
python akamai_network_list_manager.py unblock --items 198.51.100.23 --activate PRODUCTION --notify soc@example.com
python akamai_network_list_manager.py activate --environment PRODUCTION --comment "Weekly sync"
python akamai_network_list_manager.py status --environment PRODUCTION
```

Activations on PRODUCTION take a few minutes; `status` shows when the list is live.

## Tests

```bash
pip install pytest
pytest
```

## License

[MIT](LICENSE)
