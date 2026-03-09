import argparse
import threading
from typing import Optional

# ── Thread-safe print lock ────────────────────────────────────────────────────
_print_lock = threading.Lock()

# ── Text formatting ───────────────────────────────────────────────────────────
RESET = "\033[0m"
UNDERLINE = "\033[4m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"

# ── Standard colours ──────────────────────────────────────────────────────────
BLACK = "\033[30m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

# ── Bright colours ────────────────────────────────────────────────────────────
BRIGHT_BLACK = "\033[90m"
BRIGHT_RED = "\033[91m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_YELLOW = "\033[93m"
BRIGHT_BLUE = "\033[94m"
BRIGHT_MAGENTA = "\033[95m"
BRIGHT_CYAN = "\033[96m"
BRIGHT_WHITE = "\033[97m"

# ── Semantic aliases ──────────────────────────────────────────────────────────
WARN = BRIGHT_YELLOW
HEADER = BRIGHT_MAGENTA

# ── UI chrome ─────────────────────────────────────────────────────────────────
CLEAR_LINE = "\x1b[1A\x1b[2K"
DELIM = f"{BRIGHT_BLACK}{'━' * 80}{RESET}"
THIN_DELIM = f"{BRIGHT_BLACK}{'─' * 80}{RESET}"
DOUBLE_DELIM = f"{BRIGHT_YELLOW}{'═' * 80}{RESET}"

# ── Icons ─────────────────────────────────────────────────────────────────────
ICON_INFO = f"{BRIGHT_BLUE}◈{RESET}"
ICON_SUCCESS = f"{BRIGHT_GREEN}✔{RESET}"
ICON_ERROR = f"{BRIGHT_RED}✖{RESET}"
ICON_WARN = f"{BRIGHT_YELLOW}⚠{RESET}"
ICON_CMD = f"{BRIGHT_CYAN}▶{RESET}"
ICON_DEBUG = f"{BRIGHT_MAGENTA}⟡{RESET}"
ICON_HEAD = f"{BRIGHT_YELLOW}◆{RESET}"
ICON_INPUT = f"{BRIGHT_WHITE}❯{RESET}"
ICON_ROCKET = f"{BRIGHT_GREEN}🚀{RESET}"
ICON_STOP = f"{BRIGHT_RED}⏹{RESET}"
ICON_CLOCK = f"{BRIGHT_CYAN}⏱{RESET}"
ICON_NET = f"{BRIGHT_BLUE}⬡{RESET}"
ICON_LOCK = f"{BRIGHT_YELLOW}⚡{RESET}"


def make_progress_bar(current: int, total: int, width: int = 28) -> str:
    """Return a coloured progress bar string."""
    pct = current / total if total > 0 else 0
    filled = int(pct * width)
    bar = f"{BRIGHT_GREEN}{'█' * filled}{BRIGHT_BLACK}{'░' * (width - filled)}{RESET}"
    return f"[{bar}] {BOLD}{BRIGHT_WHITE}{pct:.0%}{RESET}"


class ColorfulHelpFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=150, width=300)

    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            default = self._metavar_formatter(action, action.dest)(1)[0]
            return f"{GREEN}{default}{RESET}"
        parts = []
        for option_string in action.option_strings:
            parts.append(f"{WARN}{option_string}{RESET}")
            if action.metavar not in (None, argparse.SUPPRESS):
                parts.append(f"{BLUE}{action.metavar}{RESET}")
        return ", ".join(parts)

    def add_usage(
        self, usage: Optional[str], actions: object, groups: object, prefix: Optional[str] = None
    ) -> None:
        if prefix is None:
            prefix = f"{BOLD}{BRIGHT_CYAN}Usage:{RESET} "
        super().add_usage(usage, actions, groups, prefix)

    def _format_action(self, action: argparse.Action) -> str:
        parts = super()._format_action(action)
        return parts.replace("  -", f"{CYAN}  -{RESET}").replace("show this", f"{CYAN}show this")

    def start_section(self, heading: Optional[str]) -> None:
        if heading:
            heading = f"{HEADER}{BOLD}{heading}{RESET}"
        super().start_section(heading)


# ── Core print functions (all thread-safe) ────────────────────────────────────


def printf(text: str, end: str = "\n") -> None:
    with _print_lock:
        print(text, end=end, flush=True)


def clear_line(lines: int = 1) -> None:
    with _print_lock:
        print(lines * CLEAR_LINE, end="", flush=True)


def print_error(text: str) -> None:
    printf(f"  {ICON_ERROR}  {BOLD}{BRIGHT_RED}{text}{RESET}")


def print_info(text: str, end: str = "\n") -> None:
    printf(f"  {ICON_INFO}  {BRIGHT_WHITE}{text}{RESET}", end=end)


def print_input(text: str) -> str:
    with _print_lock:
        return input(f"  {ICON_INPUT}  {BOLD}{BRIGHT_WHITE}{text}{RESET} ")


def print_cmd(text: str) -> None:
    printf(f"  {ICON_CMD}  {CYAN}{text}{RESET}")


def print_debug(text: str) -> None:
    printf(f"  {ICON_DEBUG}  {DIM}{MAGENTA}{text}{RESET}")


def print_warning(text: str) -> None:
    printf(f"  {ICON_WARN}  {BOLD}{BRIGHT_YELLOW}{text}{RESET}")


def print_success(text: str) -> None:
    printf(f"  {ICON_SUCCESS}  {BOLD}{BRIGHT_GREEN}{text}{RESET}")


def print_header(text: str) -> None:
    printf(f"\n{DELIM}")
    printf(f"  {ICON_HEAD}  {BOLD}{BRIGHT_YELLOW}{text}{RESET}")
    printf(f"{THIN_DELIM}")


# ── Aliases ───────────────────────────────────────────────────────────────────
CLEAR = clear_line
CMD = print_cmd
ERROR = print_error
DEBUG = print_debug
WARNING = print_warning
INFO = print_info
INPUT = print_input
HEAD = print_header
SUCCESS = print_success
