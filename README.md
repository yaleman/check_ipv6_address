# check_ipv6_address

## Usage

```
check_ipv6_address.py [OPTION] HOSTNAME
```

Where HOSTNAME is a TXT record to look up which has the IPv6 network you're checking.

Example: `check_ipv6_address.py _network.example.com`

Options:

```
-h, --help	Show this help message
-d, --debug	Show debug output
```

## Requirements

- Python 3.8+
- `dig` and `ip` commands in `/usr/bin/`.
