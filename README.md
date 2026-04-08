# NetArmageddon 🔥📡

A network stress testing framework for simulating device connections and evaluating router performance under load.

![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/Git-Yousfi-Neji/NetArmageddon)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
[![CI Tests](https://img.shields.io/github/actions/workflow/status/Git-Yousfi-Neji/NetArmageddon/tests.yml?branch=master)](https://github.com/Git-Yousfi-Neji/NetArmageddon/actions)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![Checked with mypy](https://img.shields.io/badge/mypy-checked-blue)](http://mypy-lang.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Documentation Status](https://img.shields.io/badge/docs-mkdocs%20material-blue)](https://git-yousfi-neji.github.io/NetArmageddon/)

## Features ✨

- [x] **DHCP Exhaustion**: Simulate hundreds of devices connecting via DHCP
- [x] **ARP Keep-Alive**: Maintain fake devices in router ARP tables
- [x] **Safety Controls**: Rate limiting and input validation
- [x] **Extensible Architecture**: Easy to add new attack modules
- [x] **CLI Interface**: Simple command-line control
- [x] **MAC Address Cycling**: Rotate through custom MAC addresses for each device
- [x] **DHCP Options Control**: Specify exact DHCP options for detailed simulation
- [x] **Device Limits**: Configure the maximum number of simulated devices
- [x] **Thread Safe Generation**: Safely generate packets across multiple threads
- [x] **Type Safe Codebase**: Full mypy type checking coverage
- [x] **Automated Code Quality**: Pre-commit hooks for formatting/linting
- [x] **Modern Testing Suite**: 90%+ test coverage with pytest
- [x] **C-Backend**: High-performance packet capture using libpcap
- [x] **BPF Filter Support**: Precise traffic selection using Berkeley Packet Filters
- [x] **Capture Limits**: Configurable duration and packet count thresholds
- [x] **Promiscuous Mode**: Optional interface promiscuity for full traffic visibility
- [x] **Deauthentication Attack**: Perform Wi-Fi deauth attacks targeting access points and clients
- [ ] **Bug fixing**: Actively working on issue fixing

## Warning ⚠️

**This tool should only be used:**
- On networks you own/control
- For educational/research purposes
- With explicit permission from network owners

Misuse may violate laws and damage network equipment. Use responsibly!

## Installation 💻

#### Clone repository
```
git clone https://github.com/Git-Yousfi-Neji/NetArmageddon.git
```
```
cd NetArmageddon
```

#### Install with development tools
```
make
```

## NetArmageddon - Network Stress Testing Framework 🚀
<!-- USAGE:netarmageddon:start -->
```console
  Usage: sudo python -m netarmageddon [-h] {dhcp,arp,traffic,deauth} ...
  
  ════════════════════════════════════════════════════════════════════════════════
      ▄▄▄       ██▀███   ███▄ ▄███▓ ▄▄▄        ▄████ ▓█████ ▓█████▄ ▓█████▄  ▒█████   ███▄    █
      ▒████▄    ▓██ ▒ ██▒▓██▒▀█▀ ██▒▒████▄     ██▒ ▀█▒▓█   ▀ ▒██▀ ██▌▒██▀ ██▌▒██▒  ██▒ ██ ▀█   █
      ▒██  ▀█▄  ▓██ ░▄█ ▒▓██    ▓██░▒██  ▀█▄  ▒██░▄▄▄░▒███   ░██   █▌░██   █▌▒██░  ██▒▓██  ▀█ ██▒
      ░██▄▄▄▄██ ▒██▀▀█▄  ▒██    ▒██ ░██▄▄▄▄██ ░▓█  ██▓▒▓█  ▄ ░▓█▄   ▌░▓█▄   ▌▒██   ██░▓██▒  ▐▌██▒
      ▓█   ▓██▒░██▓ ▒██▒▒██▒   ░██▒ ▓█   ▓██▒░▒▓███▀▒░▒████▒░▒████▓ ░▒████▓ ░ ████▓▒░▒██░   ▓██░
      ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░   ░  ░ ▒▒   ▓▒█░ ░▒   ▒ ░░ ▒░ ░ ▒▒▓  ▒  ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒
      ▒   ▒▒ ░  ░▒ ░ ▒░░  ░      ░  ▒   ▒▒ ░  ░   ░  ░ ░  ░ ░ ▒  ▒  ░ ▒  ▒   ░ ▒ ▒░ ░ ░░   ░ ▒░
      ░   ▒     ░░   ░ ░      ░     ░   ▒   ░ ░   ░    ░    ░ ░  ░  ░ ░  ░ ░ ░ ░ ▒     ░   ░ ░
          ░  ░   ░            ░         ░  ░      ░    ░  ░   ░       ░        ░ ░           ░
  
           Network Stress Testing Framework  — for networks you own
           ⚠  Use only on authorised networks. Misuse is illegal.
  ════════════════════════════════════════════════════════════════════════════════
  
  options:
    -h, --help                          show this help message and exit
  
  Supported Features:
    {dhcp,arp,traffic,deauth}
      dhcp                     ⚡ DHCP exhaustion attack
      arp                      ⬡ Maintain devices in ARP tables
      traffic                  ◈ Capture live packets to a PCAP file
      deauth                   ◆ Perform a deauth attack (requires wireless interface in monitor mode)
  
  ────────────────────────────────────────────────────────────────────────────────
    ⚠  WARNING: Use only on networks you own and control!
```
<!-- USAGE:netarmageddon:end -->

### Features:
### DHCP Exhaustion:
<!-- USAGE:dhcp:start -->
```console
  Usage: sudo python -m netarmageddon dhcp [-h] -i INTERFACE [-n NUM_DEVICES] [-O REQUEST_OPTIONS] [-s CLIENT_SRC]
  
  ════════════════════════════════════════════════════════════════════════════════
       ██████╗ ██╗  ██╗ ██████╗██████╗
       ██╔══██╗██║  ██║██╔════╝██╔══██╗
       ██║  ██║███████║██║     ██████╔╝
       ██║  ██║██╔══██║██║     ██╔═══╝
       ██████╔╝██║  ██║╚██████╗██║
       ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝     
       ⚡ Exhausting the IP pool — one DISCOVER at a time
  ════════════════════════════════════════════════════════════════════════════════
  
  options:
    -h, --help                               show this help message and exit
    -i, --interface INTERFACE                Network interface to use (e.g. eth0)
    -n, --num-devices NUM_DEVICES            Number of fake devices to simulate
    -O, --request-options REQUEST_OPTIONS    Comma-separated DHCP options (e.g. "1,3,6" or "1-10,15")
    -s, --client-src CLIENT_SRC              Comma-separated list of MAC addresses to cycle through
```
<!-- USAGE:dhcp:end -->

### ARP Keep-Alive:
<!-- USAGE:arp:start -->
```console
  Usage: sudo python -m netarmageddon arp [-h] -i INTERFACE [-b BASE_IP] [-n NUM_DEVICES] [-m MAC_PREFIX] [-t INTERVAL] [-c CYCLES] [-M MAC[,MAC...]]
  
  ════════════════════════════════════════════════════════════════════════════════
        █████╗ ██████╗ ██████╗
       ██╔══██╗██╔══██╗██╔══██╗
       ███████║██████╔╝██████╔╝
       ██╔══██║██╔══██╗██╔═══╝
       ██║  ██║██║  ██║██║
       ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     
       ⬡ Haunting the ARP table with phantom devices
  ════════════════════════════════════════════════════════════════════════════════
  
  options:
    -h, --help                                                                         show this help message and exit
    -i, --interface INTERFACE                                                          Network interface (e.g. eth0)
    -b, --base-ip BASE_IP                                                              Base IP address (e.g. 192.168.1.)
    -n, --num-devices NUM_DEVICES                                                      Number of devices to maintain
    -m, --mac-prefix MAC_PREFIX                                                        MAC address prefix (default: de:ad:00)
    -t, --interval INTERVAL                                                            Seconds between ARP bursts
    -c, --cycles CYCLES                                                                Number of announcement cycles
    -M, --target-macs MAC[,MAC...]                                                     Comma-separated list of specific MAC addresses to keep alive (e.g. de:ad:be:ef:00:01,de:ad:be:ef:00:02). When set, --num-devices is ignored.
```
<!-- USAGE:arp:end -->

### Traffic Logger:
<!-- USAGE:traffic:start -->
```console
  Usage: sudo python -m netarmageddon traffic [-h] -i INTERFACE [-f FILTER] -o OUTPUT [-d DURATION] [-c COUNT] [-s SNAPLEN] [-p BOOL]
  
  ════════════════════════════════════════════════════════════════════════════════
     ████████╗██████╗  █████╗ ███████╗███████╗██╗ ██████╗
     ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝
        ██║   ██████╔╝███████║█████╗  █████╗  ██║██║
        ██║   ██╔══██╗██╔══██║██╔══╝  ██╔══╝  ██║██║
        ██║   ██║  ██║██║  ██║██║     ██║     ██║╚██████╗
        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝ ╚═════╝ 
       ◈ Silently recording every packet that dares pass by
  ════════════════════════════════════════════════════════════════════════════════
  
  options:
    -h, --help                                                     show this help message and exit
    -i, --interface INTERFACE                                      Network interface (e.g. eth0)
    -f, --filter FILTER                                            BPF filter (e.g. 'tcp port 80')
    -o, --output OUTPUT                                            Output PCAP filename
    -d, --duration DURATION                                        Capture duration in seconds (0=unlimited)
    -c, --count COUNT                                              Max packets to capture (0=unlimited)
    -s, --snaplen SNAPLEN                                          Snapshot length (bytes)
    -p, --promisc BOOL                                             Promiscuous mode (true/false, yes/no, 1/0)
```
<!-- USAGE:traffic:end -->

### Deauthentication Attack:
<!-- USAGE:deauth:start -->
```console
  Usage: sudo python -m netarmageddon deauth [-h] -i NET_IFACE [-s] [-k] [-S CUSTOM_SSID] [-b CUSTOM_BSSID] [-c CUSTOM_CLIENT_MACS] [-C CUSTOM_CHANNELS [CUSTOM_CHANNELS ...]] [-a] [-D] [-d]
  
  ════════════════════════════════════════════════════════════════════════════════
       ██████╗ ███████╗ █████╗ ██╗   ██╗████████╗██╗  ██╗
       ██╔══██╗██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║  ██║
       ██║  ██║█████╗  ███████║██║   ██║   ██║   ███████║
       ██║  ██║██╔══╝  ██╔══██║██║   ██║   ██║   ██╔══██║
       ██████╔╝███████╗██║  ██║╚██████╔╝   ██║   ██║  ██║
       ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
       ◆ Severing wireless connections, one frame at a time
       ⚠  Requires a wireless interface in monitor mode
  ════════════════════════════════════════════════════════════════════════════════
  
  options:
    -h, --help                                   show this help message and exit
    -i, --iface NET_IFACE                        Network interface with monitor mode enabled (e.g. wlan0)
    -s, --skip-monitormode                       Skip automatic monitor mode setup (use if already configured)
    -k, --kill                                   Kill NetworkManager service (might cause connectivity issues)
    -S, --SSID CUSTOM_SSID                       Custom SSID name (case-insensitive)
    -b, --BSSID CUSTOM_BSSID                     Custom BSSID address (case-insensitive)
    -c, --clients CUSTOM_CLIENT_MACS             Target client MAC addresses
                                                 Example: 00:1A:2B:3C:4D:5E,00:1a:2b:3c:4d:5f
    -C, --Channels CUSTOM_CHANNELS [CUSTOM_CHANNELS ...]
                                                 Custom channels (e.g. 1 3 4)
    -a, --autostart                              Autostart de-auth loop (when single AP detected)
    -D, --Debug                                  Enable verbose debug output
    -d, --deauth-all-channels                    Enable de-auth on all available channels
```
<!-- USAGE:deauth:end -->

## Documentation 📚

Explore comprehensive project documentation to understand implementation details and usage:

- **[Usage Guide](docs/usage.md)** - Core functionality walkthrough with examples
- **[Development Setup](docs/development.md)** - Environment configuration and contribution guidelines
- **[Testing Strategy](docs/testing.md)** - Validation approach and quality assurance processes
- **[Architecture Overview](docs/architecture.md)** (Planned) - System design and component relationships

> **Note**: Documentation is actively being developed. Check back regularly for updates or [contribute](CONTRIBUTING.md) improvements!

## Contributing 🤝

We welcome contributions from the community! Here's how you can help:

### How to Contribute
1. **Report Bugs**
   Open an [issue](https://github.com/Git-Yousfi-Neji/NetArmageddon/issues) with detailed reproduction steps
2. **Suggest Features**
   Propose new modules/improvements via Discussions

### Development Workflow 🛠️

#### 1. Fork and clone the repository
```
git clone https://github.com/Git-Yousfi-Neji/NetArmageddon.git
```
#### 2. Set up development environment
```
make install
```
#### 3. Create feature branch
```
git checkout -b feature/awesome-feature
```
#### 4. Install dev dependencies
```
pip install -r dev-requirements.txt
```
#### 5. Commit changes with semantic messages
```
git commit -m "feat: add packet validation system"
```
#### 6. Push and open PR
```
git push origin feature/awesome-feature
```
### Code Quality Requirements
- 100% type coverage with mypy

- Black-formatted code

- Passing flake8 checks

- Documented public APIs

- Test coverage for new features

## License 📜
This project is licensed under [LICENSE](LICENSE)
