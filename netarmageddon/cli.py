import argparse
import logging
from typing import List
from .core import DHCPExhaustion, ARPKeepAlive
import time

def configure_logging():
    """Set up logging configuration"""
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO
    )

def parse_option_range(option_str: str) -> List[int]:
    """Convert '1,3-5,7' -> [1,3,4,5,7]; raises ValueError on malformed or descending ranges."""
    if not option_str:
        raise ValueError("Option string is empty")

    options: List[int] = []
    for part in option_str.split(','):
        if not part:
            # catches cases like "1,,2"
            raise ValueError(f"Empty segment in option string: '{option_str}'")

        if '-' in part:
            bounds = part.split('-', 1)
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

def main():
    """Command-line interface entry point"""
    configure_logging()
    
    parser = argparse.ArgumentParser(
        description="NetArmageddon - Network Stress Testing Framework",
        epilog="WARNING: Use only on networks you own and control!"
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True)

    # DHCP attack subcommand
    dhcp_parser = subparsers.add_parser("dhcp", help="DHCP exhaustion attack")
    dhcp_parser.add_argument("-i", "--interface", required=True,
                           help="Network interface to use")

    dhcp_parser.add_argument("-n", "--num-devices", type=int, default=50,
                           help="Number of fake devices to simulate")

    dhcp_parser.add_argument('-O', '--request-options',
                           type=parse_option_range,
                           default=list(range(81)),  # Default 0-80
                           help='Comma-separated DHCP options to request (e.g. "1,3,6" or "1-10,15")')

    # ARP attack subcommand
    arp_parser = subparsers.add_parser("arp", help="ARP keep-alive attack")
    arp_parser.add_argument("-i", "--interface", required=True,
                          help="Network interface to use")
    arp_parser.add_argument("-b", "--base-ip", required=True,
                          help="Base IP address (e.g., 192.168.1.)")
    arp_parser.add_argument("-n", "--num-devices", type=int, default=50,
                          help="Number of devices to maintain")

    args = parser.parse_args()

    try:
        if args.command == "dhcp":
            attack = DHCPExhaustion(args.interface, args.num_devices)
        elif args.command == "arp":
            attack = ARPKeepAlive(args.interface, args.base_ip, args.num_devices)

        with attack:
            while True:
                time.sleep(1)
                
    except KeyboardInterrupt:
        attack.stop()
        logging.info("\nAttack stopped by user")
    except Exception as e:
        logging.error(f"Critical error: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()