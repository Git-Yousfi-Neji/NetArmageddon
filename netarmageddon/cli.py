import argparse
import logging
import os
import sys
import time
import signal
from typing import List

from netarmageddon.utils.config_loader import ConfigLoader
from netarmageddon.core.traffic import TrafficLogger

from .core import ARPKeepAlive, DHCPExhaustion, Interceptor
from .utils.banners import (
    get_arp_banner,
    get_deauth_banner,
    get_dhcp_banner,
    get_general_banner,
    get_traffic_banner,
)
from .utils.output_manager import (
    BLUE,
    BRIGHT_RED,
    BRIGHT_YELLOW,
    GREEN,
    RESET,
    WARNING,
    ColorfulHelpFormatter,
)

# Allow help without root privileges
if any(arg in sys.argv for arg in ("-h", "--help")):
    os.environ["ALLOW_HELP_WITHOUT_ROOT"] = "1"


def check_root_privileges() -> None:
    if not os.getenv("ALLOW_HELP_WITHOUT_ROOT") and os.geteuid() != 0:
        print(f"{BRIGHT_RED}This script requires root privileges!{RESET}")
        sys.exit(1)


def configure_logging() -> None:
    """Set up logging configuration"""
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
    )


def validate_mac(mac: str) -> str:
    """Validate MAC address format"""
    mac = mac.strip().lower()
    if len(mac) != 17:
        raise argparse.ArgumentTypeError(f"{BRIGHT_RED}Invalid MAC length{RESET}")

    parts = mac.split(":")
    if len(parts) != 6:
        raise argparse.ArgumentTypeError(f"{BRIGHT_RED}Invalid MAC format{RESET}")

    if not all(len(p) == 2 and p.isalnum() for p in parts):
        raise argparse.ArgumentTypeError(f"{BRIGHT_RED}Invalid MAC characters{RESET}")

    return mac


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
            raise ValueError(f"Empty segment in option string: '{option_str}'")

        if "-" in part:
            bounds = part.split("-", 1)
            if len(bounds) != 2 or not bounds[0] or not bounds[1]:
                raise ValueError(f"Malformed range: '{part}'")
            (start_str, end_str) = bounds
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
        description=get_general_banner(),
        epilog=f"{BRIGHT_RED}{BRIGHT_YELLOW}[WARNING] Use only on networks you own and control!{RESET}",
        formatter_class=ColorfulHelpFormatter,
        prog="sudo python -m netarmageddon",
    )

    subparsers = parser.add_subparsers(dest="command", required=True, title="Supported Features")

    # DHCP attack subcommand
    dhcp_parser = subparsers.add_parser(
        "dhcp",
        help=f"{GREEN}DHCP exhaustion attack{RESET}",
        description=get_dhcp_banner(),
        formatter_class=ColorfulHelpFormatter,
    )
    dhcp_parser.add_argument(
        "-i",
        "--interface",
        required=True,
        default=ConfigLoader.get("attacks", "dhcp", "default_interface", default="lo"),
        help=f"Network interface to use ({BLUE}e.g. eth0{RESET})",
    )
    dhcp_parser.add_argument(
        "-n",
        "--num-devices",
        type=int,
        default=ConfigLoader.get("attacks", "dhcp", "default_num_devices", default=50),
        help="Number of fake devices to simulate",
    )
    dhcp_parser.add_argument(
        "-O",
        "--request-options",
        type=parse_option_range,
        default=ConfigLoader.get("attacks", "dhcp", "default_request_options", default="1,5,9"),
        help=f'Comma-separated DHCP options ({BLUE}e.g. "1,3,6" or "1-10,15"{RESET})',
    )
    dhcp_parser.add_argument(
        "-s",
        "--client-src",
        type=lambda x: x.split(","),
        default=ConfigLoader.get("attacks", "dhcp", "default_client_src", default=[]),
        help=f"Comma-separated list of {BLUE}MAC addresses{RESET} to cycle through",
    )

    # ARP attack subcommand
    arp_parser = subparsers.add_parser(
        "arp",
        help=f"{GREEN}Maintain devices in ARP tables{RESET}",
        description=get_arp_banner(),
        formatter_class=ColorfulHelpFormatter,
    )
    arp_parser.add_argument(
        "-i",
        "--interface",
        required=True,
        default=ConfigLoader.get("attacks", "arp", "default_interface", default="lo"),
        help=f"Network interface ({BLUE}e.g. eth0{RESET})",
    )
    arp_parser.add_argument(
        "-b",
        "--base-ip",
        default=ConfigLoader.get("attacks", "arp", "default_base_ip", default="192.168.1."),
        help=f"Base IP address ({BLUE}e.g. 192.168.1.{RESET})",
    )
    arp_parser.add_argument(
        "-n",
        "--num-devices",
        type=int,
        default=ConfigLoader.get("attacks", "arp", "default_num_devices", default=50),
        help="Number of devices to maintain",
    )
    arp_parser.add_argument(
        "-m",
        "--mac-prefix",
        default=ConfigLoader.get("attacks", "arp", "default_mac_prefix", default="de:ad:00"),
        help=f"MAC address prefix ({BLUE}default: de:ad:00{RESET})",
    )
    arp_parser.add_argument(
        "-t",
        "--interval",
        type=float,
        default=ConfigLoader.get("attacks", "arp", "default_interval", default=5.0),
        help="Seconds between ARP bursts",
    )
    arp_parser.add_argument(
        "-c",
        "--cycles",
        type=int,
        default=ConfigLoader.get("attacks", "arp", "default_cycles", default=1),
        help="Number of announcement cycles",
    )

    # Traffic-logger subcommand
    traffic_parser = subparsers.add_parser(
        "traffic",
        help=f"{GREEN}Capture live packets to a PCAP file{RESET}",
        description=get_traffic_banner(),
        formatter_class=ColorfulHelpFormatter,
    )
    traffic_parser.add_argument(
        "-i",
        "--interface",
        required=True,
        default=ConfigLoader.get("attacks", "traffic", "default_interface", default="lo"),
        help=f"Network interface ({BLUE}e.g. eth0{RESET})",
    )
    traffic_parser.add_argument(
        "-f",
        "--filter",
        default=ConfigLoader.get("attacks", "traffic", "default_filter", default="tcp port 80"),
        help=f"BPF filter ({BLUE}e.g. 'tcp port 80'{RESET})",
    )
    traffic_parser.add_argument(
        "-o",
        "--output",
        required=True,
        default=ConfigLoader.get(
            "attacks", "traffic", "default_output_file", default="capture.pcap"
        ),
        help="Output PCAP filename",
    )
    traffic_parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=ConfigLoader.get("attacks", "traffic", "default_duration", default=0),
        help="Capture duration in seconds (0=unlimited)",
    )
    traffic_parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=ConfigLoader.get("attacks", "traffic", "default_count", default=0),
        help="Max packets to capture (0=unlimited)",
    )
    traffic_parser.add_argument(
        "-s",
        "--snaplen",
        type=int,
        default=ConfigLoader.get("attacks", "traffic", "default_snaplen", default=65535),
        help="Snapshot length (bytes)",
    )
    traffic_parser.add_argument(
        "-p",
        "--promisc",
        action="store_true",
        default=ConfigLoader.get("attacks", "traffic", "default_promisc", default=True),
        help="Enable promiscuous mode",
    )

    # DEAUTH subcommand
    deauth_parser = subparsers.add_parser(
        "deauth",
        help=f"{GREEN}Perform a deauth attack (requires wireless interface in monitor mode){RESET}",
        formatter_class=ColorfulHelpFormatter,
        description=get_deauth_banner(),
    )

    deauth_parser.add_argument(
        "-i",
        "--iface",
        default=ConfigLoader.get("attacks", "deauth", "default_interface", default="lo"),
        help=f"Network interface with monitor mode enabled ({BLUE}e.g. wlan0{RESET})",
        action="store",
        dest="net_iface",
        required=True,
    )

    deauth_parser.add_argument(
        "-s",
        "--skip-monitormode",
        help=f"Skip automatic monitor mode setup ({WARNING}use if already configured{RESET})",
        action="store_true",
        default=ConfigLoader.get("attacks", "deauth", "default_monitormode", default=False),
        dest="skip_monitormode",
        required=False,
    )

    deauth_parser.add_argument(
        "-k",
        "--kill",
        help=f"{BRIGHT_RED}Kill NetworkManager service{RESET} (might cause connectivity issues)",
        action="store_true",
        default=ConfigLoader.get("attacks", "deauth", "default_kill", default=False),
        dest="kill_networkmanager",
        required=False,
    )
    deauth_parser.add_argument(
        "-S",
        "--SSID",
        help=f"Custom SSID name {BLUE}(case-insensitive){RESET}",
        action="store",
        default=ConfigLoader.get("attacks", "deauth", "default_ssid", default=None),
        dest="custom_ssid",
        required=False,
    )
    deauth_parser.add_argument(
        "-b",
        "--BSSID",
        help=f"Custom BSSID address {BLUE}(case-insensitive){RESET}",
        action="store",
        default=ConfigLoader.get("attacks", "deauth", "default_bssid", default=None),
        dest="custom_bssid",
        required=False,
    )
    deauth_parser.add_argument(
        "-c",
        "--clients",
        help=f"Target client MAC addresses\n{BLUE}Example: 00:1A:2B:3C:4D:5E,00:1a:2b:3c:4d:5f{RESET}",
        action="store",
        default=ConfigLoader.get("attacks", "deauth", "default_clients", default=None),
        type=lambda x: [validate_mac(m) for m in x.split(",")],
        dest="custom_client_macs",
        required=False,
    )
    deauth_parser.add_argument(
        "-C",
        "--Channels",
        help=f"Custom channels {BLUE}(e.g. 1 3 4){RESET}",
        action="store",
        nargs="+",
        default=ConfigLoader.get("attacks", "deauth", "default_channels", default=None),
        dest="custom_channels",
        required=False,
    )
    deauth_parser.add_argument(
        "-a",
        "--autostart",
        help=f"Autostart de-auth loop {BLUE}(when single AP detected){RESET}",
        action="store_true",
        default=ConfigLoader.get("attacks", "deauth", "default_autostart", default=False),
        dest="autostart",
        required=False,
    )
    deauth_parser.add_argument(
        "-D",
        "--Debug",
        help=f"{WARNING}Enable verbose debug output{RESET}",
        action="store_true",
        default=ConfigLoader.get("attacks", "deauth", "default_debug", default=False),
        dest="debug_mode",
        required=False,
    )
    deauth_parser.add_argument(
        "-d",
        "--deauth-all-channels",
        help=f"Enable de-auth on {BLUE}all available channels{RESET}",
        action="store_true",
        default=ConfigLoader.get("attacks", "deauth", "default_deauth_all", default=False),
        dest="deauth_all_channels",
        required=False,
    )

    args = parser.parse_args()

    try:
        if args.command == "dhcp":
            attack = DHCPExhaustion(
                interface=args.interface,
                num_devices=args.num_devices,
                request_options=args.request_options,
                client_src=args.client_src,
            )
            signal.signal(signal.SIGINT, lambda sig, frame: attack.user_abort())
            attack.start()

        elif args.command == "arp":
            attack = ARPKeepAlive(
                interface=args.interface,
                base_ip=args.base_ip,
                num_devices=args.num_devices,
                interval=args.interval,
                cycles=args.cycles,
            )
            signal.signal(signal.SIGINT, lambda sig, frame: attack.user_abort())
            attack.start()

        elif args.command == "traffic":
            attack = TrafficLogger(
                interface=args.interface,
                bpf_filter=args.filter,
                output_file=args.output,
                duration=args.duration,
                count=args.count,
                snaplen=args.snaplen,
                promisc=args.promisc,
            )
            signal.signal(signal.SIGINT, lambda sig, frame: attack.user_abort())
            attack.start()

        elif args.command == "deauth":
            attack = Interceptor(
                net_iface=args.net_iface,
                skip_monitor_mode_setup=args.skip_monitormode,
                kill_networkmanager=args.kill_networkmanager,
                ssid_name=args.custom_ssid,
                bssid_addr=args.custom_bssid,
                custom_client_macs=args.custom_client_macs,
                custom_channels=args.custom_channels,
                deauth_all_channels=args.deauth_all_channels,
                autostart=args.autostart,
                debug_mode=args.debug_mode,
            )
            # signal.signal(signal.SIGINT, Interceptor.user_abort)
            signal.signal(signal.SIGINT, lambda sig, frame: attack.user_abort())
            attack.start()

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
