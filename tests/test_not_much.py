""" doesn't test much... """

from check_ipv6_address import get_txt_record, setup_logging


def test_get_txt_record() -> None:
    """tests the get_txt_record function"""
    get_txt_record(setup_logging(True), "google.com")
