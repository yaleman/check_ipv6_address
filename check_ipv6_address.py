#!/usr/bin/env python3

""" Compares a TXT record to the local ipv6 network interface
to see if the network address matches.

Convoluted test for "has the network changed". Outputs in nagios-compatible thingies.
"""

from distutils.spawn import find_executable
from ipaddress import ip_network, IPv6Network, IPv6Address, AddressValueError
import json
from json.decoder import JSONDecodeError
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

import sys

import click


def setup_logging(debug: bool) -> logging.Logger:
    """set up logging"""

    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
    return logging.getLogger()


def get_txt_record(logger: logging.Logger, hostname: str) -> str:
    """gets the network ipv6 address"""

    dig = find_executable("dig")
    if dig is None:
        logger.error(
            "Failed to find dig command in path, bailing",
        )
        raise FileNotFoundError("Failed to find dig command in path, bailing")

    dig_command = Path(dig)

    full_command = f"{dig_command.resolve().as_posix()} +short TXT {hostname}"
    digresult = os.popen(full_command)

    dig_result = digresult.read().strip().replace('"', "")
    if not dig_result:
        logger.error("Empty result from command: %s", full_command)
        sys.exit(1)
    return dig_result


def get_interfaces(logger: logging.Logger) -> List[Dict[str, Any]]:
    """returns a list of interfaces from the result of 'ip -j add show'"""
    ipcmd_path = find_executable("ip")
    if ipcmd_path is None:
        logger.error("Failed to find 'ip' command, bailing")
        raise FileNotFoundError("Failed to find 'ip' command in path, bailing")

    result = os.popen(f"{ipcmd_path} -j add show")
    resultstring = result.read()

    try:
        resultdata: List[Dict[str, Any]] = json.loads(resultstring)
    except JSONDecodeError as error_message:
        logger.error("Failed to decode JSON: %s", error_message)
        logger.error("Input data:\n %s", resultstring)
        sys.exit(1)
    if not resultdata:
        logger.error("Found no interfaces, bailing")
        sys.exit(1)
    return resultdata


ULA_RANGE = IPv6Network("fc00::/7")


def is_ula(logger: logging.Logger, address: Dict[str, Any]) -> bool:
    """checks if it's an IPv6 ULA"""
    try:
        parsed_ipv6_address = IPv6Address(address.get("local"))
        if parsed_ipv6_address in ULA_RANGE:
            logger.debug("%s is a Unique Local Address, skipping.", parsed_ipv6_address)
            return True
    except AddressValueError as addressvalue:
        logger.debug("%s did not parse as ipv6: %s", address.get("local"), addressvalue)
    return False


@click.command()
@click.argument("hostname")
@click.option("--debug", "-d", is_flag=True, help="Debug mode.")
def cli(hostname: str, debug: bool) -> None:
    """Command line interface"""
    logger = setup_logging(debug)

    try:
        interfaces = get_interfaces(logger)
        txtrecord = get_txt_record(logger, hostname)
    except FileNotFoundError:
        sys.exit(1)

    found_addresses = []

    for interface in interfaces:
        if "addr_info" not in interface:
            logger.debug("No address information, skipping.")
            continue

        if "flags" in interface and "LOOPBACK" in interface["flags"]:
            logger.debug("Skipping loopback: %s", interface.get("ifname"))
            continue
        if interface.get("operstate") != "UP":
            logger.debug("Skipping down interface: %s", interface.get("ifname"))
            continue

        for address in interface["addr_info"]:
            if (
                address.get("deprecated")
                or address.get("scope") == "link"
                or address.get("family") == "inet"
                or not address.get("mngtmpaddr")
            ):
                logger.debug("Skipping interface: %s", address.get("local"))
                continue
            if not is_ula(logger, address):
                found_addresses.append(address)

    if not found_addresses:
        logger.error("Couldn't find an IPv6 managment address, bailing")
        sys.exit(1)

    if len(found_addresses) > 1:
        dumping = json.dumps(found_addresses, default=str, ensure_ascii=False)
        logger.error(
            "More than one management address, that's scary! Found the following: %s",
            dumping,
        )
        sys.exit(1)

    address = found_addresses[0]
    logger.debug(json.dumps(address))
    to_parse = f"{address.get('local')}/{address.get('prefixlen')}"
    logger.debug("PARSING: %s", to_parse)

    network = ip_network(to_parse, strict=False)
    if not isinstance(network, IPv6Network):
        logger.error(
            "Not sure what went on, but %s is not an instance of IPv6Network", network
        )
        logger.debug(type(network))
        sys.exit(1)
    logger.debug("Network address: %s", network.network_address)

    logger.debug("TXT record     : %s", txtrecord)

    if str(network.network_address) != txtrecord:
        print(
            f"CRITICAL: Address should be '{txtrecord}', is '{network.network_address}'"
        )
    else:
        print(f"OK: Address is '{txtrecord}'")


if __name__ == "__main__":
    cli()  # pylint: disable=no-value-for-parameter
