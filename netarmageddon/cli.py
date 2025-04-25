import argparse
import logging
from .core import DHCPExhaustion, ARPKeepAlive

def configure_logging():
    """Set up logging configuration"""
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO
    )

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