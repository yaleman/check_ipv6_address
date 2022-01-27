#!/usr/bin/env python3

""" Compares a TXT record to the local ipv6 network interface to see if the network address matches. Convoluted test for if the network has changed. Outputs in nagios-compatible thingies.
"""

from ipaddress import ip_network, IPv6Network, IPv6Address, AddressValueError
import json
from json.decoder import JSONDecodeError
import logging
import os
import sys

if '-d' in sys.argv:
    logging.basicConfig(level=logging.DEBUG)
elif '-h' in sys.argv or '--help' in sys.argv:
    print("""Usage: check_ipv6_address.py [OPTION] HOSTNAME

Where HOSTNAME is a TXT record to look up which has the IPv6 network you're checking.

Example: check_ipv6_address.py _network.example.com

Options:

-h, --help\tShow this help message
-d, --debug\tShow debug output
""")
    sys.exit(0)
else:
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger()

if len(sys.argv) == 1:
    logger.error("Please pass a hostname to look up!")
    sys.exit(1)

if not '.' in sys.argv[-1] or sys.argv[-1] in ("-d", "--debug"):
    logger.error("Please pass a hostname to look up, got: '%s'", sys.argv[-1])
    sys.exit(1)

CMD="/usr/bin/ip"
DIG_COMMAND = "/usr/bin/dig"

ULA = IPv6Network("fc00::/7")

def get_txt_record(hostname):
    """ gets the network ipv6 address """
    if not os.path.exists(DIG_COMMAND):
        logger.error("Failed to find dig at %s, bailing", DIG_COMMAND)
        return False
    full_command = f"{DIG_COMMAND} +short TXT {hostname}"
    digresult = os.popen(full_command)

    dig_result = digresult.read().strip().replace("\"", "")
    if not dig_result:
        logger.error("Empty result from command: %s", full_command)
        return False
    return dig_result

for command in [DIG_COMMAND, CMD]:
    if not os.path.exists(command):
        logger.error("Cannot find %s, bailing!", command)
        sys.exit(1)

result = os.popen(f"{CMD} -j add show")

resultstring = result.read()

try:
    resultdata = json.loads(resultstring)
except JSONDecodeError as error_message:
    logger.error("Failed to decode JSON: %s", error_message)
    logger.error("Input data:\n %s", resultstring)
    sys.exit(1)

found_addresses = []

for interface in resultdata:
    if "LOOPBACK" in interface.get("flags"):
        logger.debug("Skipping loopback: %s", interface.get("ifname"))
        continue
    if interface.get("operstate") != "UP":
        logger.debug("Skipping down interface: %s", interface.get("ifname"))
        continue
    try:
        parsed_ipv6_address = IPv6Address(interface.get("local"))
        if parsed_ipv6_address in ULA:
            logger.debug("%s is a Unique Local Address, skipping.", parsed_ipv6_address)
            continue
    except AddressValueError as addressvalue:
        logger.debug("%s did not parse as ipv6", interface.get('local'))
    for address in interface.get("addr_info"):
        if address.get("deprecated") or address.get("scope") == "link" or address.get("family") == "inet" or not address.get("mngtmpaddr"):
            #logger.debug("Skipping interface: %s", address.get("local"))
            continue
        found_addresses.append(address)

if not found_addresses:
    logger.error("Couldn't find an IPv6 managment address, bailing")
    sys.exit(1)

if len(found_addresses) >1:

    # ERROR:root:[{"family": "inet6", "local": "fd6a:cea4:1867:4ecb:f006:7ff:feff:8a10", "prefixlen": 64, "scope": "global", "dynamic": true, "mngtmpaddr": true, "valid_life_time": 1786, "preferred_life_time": 297}, {"family": "inet6", "local": "2403:580a:2d:0:f006:7ff:feff:8a10", "prefixlen": 64, "scope": "global", "dynamic": true, "mngtmpaddr": true, "valid_life_time": 86387, "preferred_life_time": 14387}]
    dumping = json.dumps(found_addresses, default=str, ensure_ascii=False)
    logger.error("More than one management address, that's scary! Found the following: %s", dumping)
    sys.exit(1)

address = found_addresses[0]
logger.debug(json.dumps(address))
to_parse = f"{address.get('local')}/{address.get('prefixlen')}"
logger.debug("PARSING: %s", to_parse)

network = ip_network(to_parse, strict=False)
if not isinstance(network, IPv6Network):
    logger.error("Not sure what went on, but %s is not an instance of IPv6Network", network)
    logger.debug(type(network))
    sys.exit(1)
logger.debug("Network address: %s", network.network_address)

txtrecord = get_txt_record(sys.argv[-1])
logger.debug("TXT record     : %s", txtrecord)

if str(network.network_address) != txtrecord:
    print(f"CRITICAL: Address should be '{txtrecord}', is '{network.network_address}'")
else:
    print(f"OK: Address is '{txtrecord}'")
