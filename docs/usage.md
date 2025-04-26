# NetArmageddon Usage Guide

## Basic Commands

```bash
# DHCP Exhaustion (50 devices)
sudo python -m netarmageddon dhcp -i eth0 -n 50

# ARP Keep-Alive (192.168.1.x network)
sudo python -m netarmageddon arp -i eth0 -b 192.168.1.

# Combined attack (Background processes)
sudo python -m netarmageddon dhcp -i eth0 -n 100 &
sudo python -m netarmageddon arp -i eth0 -b 192.168.1. &
```

## Command Reference

### DHCP Exhaustion
| Option | Description |
|--------|-------------|
| `-i/--interface` | Network interface (required) |
| `-n/--num-devices` | Number of devices to simulate (default: 50) |

### ARP Keep-Alive
| Option | Description |
|--------|-------------|
| `-i/--interface` | Network interface (required) |
| `-b/--base-ip` | Base IP address (e.g., 192.168.1.) |
| `-n/--num-devices` | Devices to maintain (default: 50) |

## Safety Features
- Automatic rate limiting (max 100 packets/sec)
- Interface validation
- Ctrl+C graceful shutdown