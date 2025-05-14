import os
import sys

_DEVNULL = open(os.devnull, "w")
_ORIG_STDOUT = sys.stdout
_CLEAR_LINE = "\x1b[1A\x1b[2K"
DELIM = 80 * "="

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[1;33m"
BLUE = "\033[34m"


def printf(text: str, end: str = "\n") -> None:
    sys.stdout = _ORIG_STDOUT
    print(text, end=end)
    sys.stdout = _DEVNULL


def clear_line(lines: int = 1) -> None:
    printf(lines * _CLEAR_LINE)


def print_error(text: str) -> None:
    printf(f"[{BOLD}{RED}!{RESET}] {text}")


def print_info(text: str, end: str = "\n") -> None:
    printf(f"[{BOLD}{BLUE}*{RESET}] {text}", end=end)


def print_input(text: str) -> str:
    return input(f"[{BOLD}{GREEN}<{RESET}] {text} ")


def print_cmd(text: str) -> None:
    printf(f"[{BOLD}{GREEN}>{RESET}] {text}")


def print_debug(text: str) -> None:
    printf(f"[{BOLD}{YELLOW}~{RESET}] {text}")
