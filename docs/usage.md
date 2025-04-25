# NetArmageddon Usage Guide

## Basic Commands
```bash
# DHCP Exhaustion
sudo python3 -m netarmageddon dhcp -i eth0 -n 100

# ARP Keep-Alive
sudo python3 -m netarmageddon arp -i eth0 -b 192.168.1.
```

## Configuration
Edit `config/default.yaml`:
```yaml
attacks:
  dhcp:
    max_pps: 150 # Max packets per second
```