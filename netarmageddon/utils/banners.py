from .output_manager import (
    BOLD,
    RESET,
    DIM,
    BRIGHT_RED,
    BRIGHT_GREEN,
    BRIGHT_YELLOW,
    BRIGHT_CYAN,
    BRIGHT_MAGENTA,
    BRIGHT_WHITE,
    DOUBLE_DELIM,
)


def get_dhcp_banner() -> str:
    return (
        f"\n{DOUBLE_DELIM}\n"
        f"{BRIGHT_GREEN}{BOLD}"
        f"     ██████╗ ██╗  ██╗ ██████╗██████╗ \n"
        f"     ██╔══██╗██║  ██║██╔════╝██╔══██╗\n"
        f"     ██║  ██║███████║██║     ██████╔╝\n"
        f"     ██║  ██║██╔══██║██║     ██╔═══╝ \n"
        f"     ██████╔╝██║  ██║╚██████╗██║     \n"
        f"     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝     {RESET}\n"
        f"     {DIM}{BRIGHT_WHITE}⚡ Exhausting the IP pool — one DISCOVER at a time{RESET}\n"
        f"{DOUBLE_DELIM}\n"
    )


def get_arp_banner() -> str:
    return (
        f"\n{DOUBLE_DELIM}\n"
        f"{BRIGHT_CYAN}{BOLD}"
        f"      █████╗ ██████╗ ██████╗ \n"
        f"     ██╔══██╗██╔══██╗██╔══██╗\n"
        f"     ███████║██████╔╝██████╔╝\n"
        f"     ██╔══██║██╔══██╗██╔═══╝ \n"
        f"     ██║  ██║██║  ██║██║     \n"
        f"     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     {RESET}\n"
        f"     {DIM}{BRIGHT_WHITE}⬡ Haunting the ARP table with phantom devices{RESET}\n"
        f"{DOUBLE_DELIM}\n"
    )


def get_traffic_banner() -> str:
    return (
        f"\n{DOUBLE_DELIM}\n"
        f"{BRIGHT_YELLOW}{BOLD}"
        f"   ████████╗██████╗  █████╗ ███████╗███████╗██╗ ██████╗ \n"
        f"   ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝ \n"
        f"      ██║   ██████╔╝███████║█████╗  █████╗  ██║██║      \n"
        f"      ██║   ██╔══██╗██╔══██║██╔══╝  ██╔══╝  ██║██║      \n"
        f"      ██║   ██║  ██║██║  ██║██║     ██║     ██║╚██████╗ \n"
        f"      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝ ╚═════╝ {RESET}\n"
        f"     {DIM}{BRIGHT_WHITE}◈ Silently recording every packet that dares pass by{RESET}\n"
        f"{DOUBLE_DELIM}\n"
    )


def get_deauth_banner() -> str:
    return (
        f"\n{DOUBLE_DELIM}\n"
        f"{BRIGHT_RED}{BOLD}"
        f"     ██████╗ ███████╗ █████╗ ██╗   ██╗████████╗██╗  ██╗\n"
        f"     ██╔══██╗██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║  ██║\n"
        f"     ██║  ██║█████╗  ███████║██║   ██║   ██║   ███████║\n"
        f"     ██║  ██║██╔══╝  ██╔══██║██║   ██║   ██║   ██╔══██║\n"
        f"     ██████╔╝███████╗██║  ██║╚██████╔╝   ██║   ██║  ██║\n"
        f"     ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝{RESET}\n"
        f"     {DIM}{BRIGHT_WHITE}◆ Severing wireless connections, one frame at a time{RESET}\n"
        f"     {BRIGHT_YELLOW}⚠  Requires a wireless interface in monitor mode{RESET}\n"
        f"{DOUBLE_DELIM}\n"
    )


def get_general_banner() -> str:
    return (
        f"\n{DOUBLE_DELIM}\n"
        f"{BRIGHT_MAGENTA}{BOLD}"
        f"    ▄▄▄       ██▀███   ███▄ ▄███▓ ▄▄▄        ▄████ ▓█████ ▓█████▄ ▓█████▄  ▒█████   ███▄    █\n"
        f"    ▒████▄    ▓██ ▒ ██▒▓██▒▀█▀ ██▒▒████▄     ██▒ ▀█▒▓█   ▀ ▒██▀ ██▌▒██▀ ██▌▒██▒  ██▒ ██ ▀█   █\n"
        f"    ▒██  ▀█▄  ▓██ ░▄█ ▒▓██    ▓██░▒██  ▀█▄  ▒██░▄▄▄░▒███   ░██   █▌░██   █▌▒██░  ██▒▓██  ▀█ ██▒\n"
        f"    ░██▄▄▄▄██ ▒██▀▀█▄  ▒██    ▒██ ░██▄▄▄▄██ ░▓█  ██▓▒▓█  ▄ ░▓█▄   ▌░▓█▄   ▌▒██   ██░▓██▒  ▐▌██▒\n"
        f"    ▓█   ▓██▒░██▓ ▒██▒▒██▒   ░██▒ ▓█   ▓██▒░▒▓███▀▒░▒████▒░▒████▓ ░▒████▓ ░ ████▓▒░▒██░   ▓██░\n"
        f"    ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░   ░  ░ ▒▒   ▓▒█░ ░▒   ▒ ░░ ▒░ ░ ▒▒▓  ▒  ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒\n"
        f"    ▒   ▒▒ ░  ░▒ ░ ▒░░  ░      ░  ▒   ▒▒ ░  ░   ░  ░ ░  ░ ░ ▒  ▒  ░ ▒  ▒   ░ ▒ ▒░ ░ ░░   ░ ▒░\n"
        f"    ░   ▒     ░░   ░ ░      ░     ░   ▒   ░ ░   ░    ░    ░ ░  ░  ░ ░  ░ ░ ░ ░ ▒     ░   ░ ░\n"
        f"        ░  ░   ░            ░         ░  ░      ░    ░  ░   ░       ░        ░ ░           ░{RESET}\n"
        f"\n"
        f"         {BRIGHT_WHITE}{BOLD}Network Stress Testing Framework{RESET}  {DIM}— for networks you own{RESET}\n"
        f"         {BRIGHT_RED}⚠  Use only on authorised networks. Misuse is illegal.{RESET}\n"
        f"{DOUBLE_DELIM}\n"
    )
