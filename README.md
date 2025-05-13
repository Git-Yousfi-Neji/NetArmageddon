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
- [x] **ARP Keep- [x]Alive**: Maintain fake devices in router ARP tables
- [x] **Safety Controls**: Rate limiting and input validation
- [x] **Extensible Architecture**: Easy to add new attack modules
- [x] **CLI Interface**: Simple command- [x]line control
- [x] **MAC Address Cycling**: Rotate through custom MAC addresses for each device
- [x] **DHCP Options Control**: Specify exact DHCP options for detailed simulation
- [x] **Device Limits**: Configure the maximum number of simulated devices
- [x] **Thread- [x]Safe Generation**: Safely generate packets across multiple threads
- [x] **Type- [x]Safe Codebase**: Full mypy type checking coverage
- [x] **Automated Code Quality**: Pre- [x]commit hooks for formatting/linting
- [x] **Modern Testing Suite**: 90%+ test coverage with pytest
- [x] **C- [x]Backend**: High- [x]performance packet capture using libpcap
- [x] **BPF Filter Support**: Precise traffic selection using Berkeley Packet Filters
- [x] **Capture Limits**: Configurable duration and packet count thresholds
- [x] **Promiscuous Mode**: Optional interface promiscuity for full traffic visibility
- [ ] **Bug fixing**: Working on issue fixing

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
cd NetArmageddon
```

#### Install with development tools
```
make
```

## Usage 🚀

#### DHCP Exhaustion (50 devices)
```
sudo python -m netarmageddon dhcp -i eth0 -n 50
```

#### ARP Keep-Alive (192.168.1.x network)
```
sudo python -m netarmageddon arp -i eth0 -b 192.168.1.
```

#### Combined attack (Ctrl+C to stop)
```
sudo python -m netarmageddon dhcp -i eth0 -n 100 & \
sudo python -m netarmageddon arp -i eth0 -b 192.168.1.
```

#### Limited device count with custom MACs
```
sudo python -m netarmageddon dhcp -i eth0 -n 10 -s de:ad:be:ef:13:37,ca:fe:ba:be:00:11
```

#### Specific DHCP options request
```
sudo python -m netarmageddon dhcp -i eth0 -O 1,3,6,15 -n 5
```

#### Traffic Capture (HTTP traffic, 60 seconds)
```
sudo python -m netarmageddon traffic -i eth0 -f "tcp port 80" -o web.pcap -d 60
```
#### Continuous Packet Capture
```
sudo python -m netarmageddon traffic -i wlan0 -o full_capture.pcap -d 0
```
## Documentation 📚

Explore comprehensive project documentation to understand implementation details and usage:

- **[Usage Guide](docs/usage.md)** - Core functionality walkthrough with examples
- **[Development Setup](docs/development.md)** - Environment configuration and contribution guidelines
- **[Testing Strategy](docs/testing.md)** - Validation approach and quality assurance processes
- **[API Reference](docs/api.md)** (WIP) - Module/class specifications and interfaces
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
### Code Quality Requirements
> - 100% type coverage with mypy

> - Black-formatted code

> - Passing flake8 checks

> - Documented public APIs

> - Test coverage for new features

## License 📜
This project is licensed under [LICENSE](LICENSE)
