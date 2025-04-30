import argparse
import logging
import os
import sys
import time
from typing import List

from .core import ARPKeepAlive, DHCPExhaustion
from .core.base_attack import BaseAttack


def check_root_privileges() -> None:
    if os.geteuid() != 0:
        print("This script requires root privileges!")
        sys.exit(1)


def configure_logging() -> None:
    """Set up logging configuration"""
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )


def parse_mac_address(arg_list: List[str]) -> argparse.Namespace:
    """
    Normalizes MAC addresses (converts '-' to ':').
    """
    parser = argparse.ArgumentParser(
        prog="netarmageddon dhcp", description="DHCP exhaustion attack arguments"
    )

    parser.add_argument(
        "-s",
        "--client-src",
        type=lambda x: x.split(","),
        default=[],
        help="Comma-separated list of MAC addresses to cycle through",
    )

    args = parser.parse_args(arg_list)

    # Normalize any hyphens in MAC addresses to colons
    if args.client_src:
        normalized = []
        for mac in args.client_src:
            # convert AA-BB-CC-DD-EE-FF → aa:bb:cc:dd:ee:ff
            m = mac.strip().lower().replace("-", ":")
            normalized.append(m)
        args.client_src = normalized

    return args


def parse_option_range(option_str: str) -> List[int]:
    """
    Convert '1,3-5,7' -> [1,3,4,5,7];
    raises ValueError on malformed or descending ranges.
    """
    if not option_str:
        raise ValueError("Option string is empty")

    options: List[int] = []
    for part in option_str.split(","):
        if not part:
            # catches cases like "1,,2"
            raise ValueError(f"Empty segment in option string: '{option_str}'")

        if "-" in part:
            bounds = part.split("-", 1)
            if len(bounds) != 2 or not bounds[0] or not bounds[1]:
                raise ValueError(f"Malformed range: '{part}'")
            start_str, end_str = bounds
            try:
                start = int(start_str)
                end = int(end_str)
            except ValueError:
                raise ValueError(f"Non-integer in range: '{part}'")
            if start > end:
                raise ValueError(f"Descending range not allowed: '{part}'")
            options.extend(range(start, end + 1))
        else:
            try:
                n = int(part)
            except ValueError:
                raise ValueError(f"Non-integer option code: '{part}'")
            options.append(n)

    return options


def main() -> None:
    """Command-line interface entry point"""
    check_root_privileges()
    configure_logging()

    parser = argparse.ArgumentParser(
        description="NetArmageddon - Network Stress Testing Framework",
        epilog="WARNING: Use only on networks you own and control!",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # DHCP attack subcommand
    dhcp_parser = subparsers.add_parser("dhcp", help="DHCP exhaustion attack")
    dhcp_parser.add_argument(
        "-i", "--interface", required=True, help="Network interface to use"
    )

    dhcp_parser.add_argument(
        "-n",
        "--num-devices",
        type=int,
        default=50,
        help="Number of fake devices to simulate",
    )

    dhcp_parser.add_argument(
        "-O",
        "--request-options",
        type=parse_option_range,
        default=list(range(81)),  # Default 0-80
        help='Comma-separated DHCP options to request (e.g. "1,3,6" or "1-10,15")',
    )

    dhcp_parser.add_argument(
        "-s",
        "--client-src",
        type=lambda x: x.split(","),
        help="Comma-separated list of MAC addresses to cycle through",
    )

    # ARP attack subcommand
    arp_parser = subparsers.add_parser("arp", help="Maintain devices in ARP tables")

    arp_parser.add_argument(
        "-i", "--interface", required=True, help="Network interface to use (e.g., eth0)"
    )

    arp_parser.add_argument(
        "-b", "--base-ip", required=True, help="Base IP address (e.g., 192.168.1.)"
    )

    arp_parser.add_argument(
        "-n",
        "--num-devices",
        type=int,
        default=50,
        help="Number of devices to maintain",
    )

    arp_parser.add_argument(
        "-m",
        "--mac-prefix",
        default="02:00:00",
        help="MAC address prefix (default: 02:00:00)",
    )

    arp_parser.add_argument(
        "-t",
        "--interval",
        type=float,
        default=5.0,
        help="Seconds between each ARP burst (default: 5.0)",
    )

    arp_parser.add_argument(
        "-c",
        "--cycles",
        type=int,
        default=1,
        help="Number of ARP announcement cycles to perform (default: 1)",
    )

    args = parser.parse_args()

    try:
        # declare with the abstract base type so both branches type‐check
        attack: BaseAttack
        if args.command == "dhcp":
            attack = DHCPExhaustion(
                interface=args.interface,
                num_devices=args.num_devices,
                request_options=args.request_options,
                client_src=args.client_src,
            )

        elif args.command == "arp":
            attack = ARPKeepAlive(
                interface=args.interface,
                base_ip=args.base_ip,
                num_devices=args.num_devices,
                interval=args.interval,
                cycles=args.cycles,
            )

        with attack:
            while attack.running:
                time.sleep(1)

    except KeyboardInterrupt:
        attack.stop()
        logging.info("\nAttack stopped by user")
    except Exception as e:
        logging.error(f"Critical error: {str(e)}")
        exit(1)


if __name__ == "__main__":
    main()
