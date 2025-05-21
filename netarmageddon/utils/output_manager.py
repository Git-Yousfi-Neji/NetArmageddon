import argparse
import os
import sys

DEVNULL = open(os.devnull, "w")
ORIG_STDOUT = sys.stdout

# Formatting
CLEAR_LINE = "\x1b[1A\x1b[2K"
DELIM = 80 * "="
RESET = "\033[0m"
UNDERLINE = "\033[4m"
BOLD = "\033[1m"
WARNING = "\033[93m"
HEADER = "\033[95m"

# Standard colors
BLACK = "\033[30m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

# Bright colors
BRIGHT_BLACK = "\033[90m"
BRIGHT_RED = "\033[91m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_YELLOW = "\033[93m"
BRIGHT_BLUE = "\033[94m"
BRIGHT_MAGENTA = "\033[95m"
BRIGHT_CYAN = "\033[96m"
BRIGHT_WHITE = "\033[97m"


class ColorfulHelpFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=150, width=300)

    def _format_action_invocation(self, action):
        if not action.option_strings:
            default = self._metavar_formatter(action, action.dest)(1)[0]
            return f"{GREEN}{default}{RESET}"
        else:
            parts = []
            for option_string in action.option_strings:
                parts.append(f"{WARNING}{option_string}{RESET}")
                if action.metavar not in (None, argparse.SUPPRESS):
                    parts.append(f"{BLUE}{action.metavar}{RESET}")
            return ", ".join(parts)

    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = f"{BOLD}Usage:{RESET} "
        super().add_usage(usage, actions, groups, prefix)

    def _format_action(self, action):
        parts = super()._format_action(action)
        return parts.replace("  -", f"{CYAN}  -{RESET}").replace(
            "show this", f"{CYAN}show this"
        )

    def start_section(self, heading):
        if heading:
            heading = f"{HEADER}{heading}{RESET}"
        super().start_section(heading)


def printf(text: str, end: str = "\n") -> None:
    sys.stdout = ORIG_STDOUT
    print(text, end=end)
    sys.stdout = DEVNULL


def clear_line(lines: int = 1) -> None:
    printf(lines * CLEAR_LINE)


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
