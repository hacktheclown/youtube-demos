import sys

from utils import constants

def print_err(msg: str) -> None:
    print(constants.COLOR_FAIL + msg)
    sys.exit(1)

def print_debug(msg: str,
                enabled: bool) -> None:
    if enabled:
        print(constants.COLOR_DEBUG + msg)

def print_ok(msg: str) -> None:
    print(constants.COLOR_OK + msg)

def print_info(msg: str) -> None:
    print(constants.COLOR_INFO + msg)
