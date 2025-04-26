# NetArmageddon 🔥📡

A network stress testing framework for simulating device connections and evaluating router performance under load.

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/Git-Yousfi-Neji/NetArmageddon/tests.yml?branch=master)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/Git-Yousfi-Neji/NetArmageddon)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-GPL--3.0-important)

## Features ✨

- **DHCP Exhaustion**: Simulate hundreds of devices connecting via DHCP
- **ARP Keep-Alive**: Maintain fake devices in router ARP tables
- **Safety Controls**: Rate limiting and input validation
- **Extensible Architecture**: Easy to add new attack modules
- **CLI Interface**: Simple command-line control

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

#### Install dependencies
```
pip install -r requirements.txt
```

## Usage 🚀

# DHCP Exhaustion (50 devices)
```
sudo python -m netarmageddon dhcp -i eth0 -n 50
```

# ARP Keep-Alive (192.168.1.x network)
```
sudo python -m netarmageddon arp -i eth0 -b 192.168.1.
```

# Combined attack (Ctrl+C to stop)
```
sudo python -m netarmageddon dhcp -i eth0 -n 100 & \
sudo python -m netarmageddon arp -i eth0 -b 192.168.1.
```

## Documentation 📚

Explore comprehensive project documentation to understand implementation details and usage:

- **[Usage Guide](docs/usage.md)** - Core functionality walkthrough with examples  
- **[Development Setup](docs/development.md)** - Environment configuration and contribution guidelines  
- **[Testing Strategy](docs/testing.md)** - Validation approach and quality assurance processes  
- **[API Reference](docs/api.md)** (WIP) - Module/class specifications and interfaces  
- **[Architecture Overview](docs/architecture.md)** (Planned) - System design and component relationships  

> **Note**: Documentation is actively being developed. Check back regularly for updates or [contribute](CONTRIBUTING.md) improvements!

For live documentation, visit our [GitHub Pages site](https://git-yousfi-neji.github.io/NetArmageddon/) (Coming Soon).

## Contributing 🤝

We welcome contributions from the community! Here's how you can help:

### How to Contribute
1. **Report Bugs**  
   Open an [issue](https://github.com/Git-Yousfi-Neji/NetArmageddon/issues) with detailed reproduction steps
2. **Suggest Features**  
   Propose new modules/improvements via Discussions

### Development Workflow

# 1. Fork and clone the repository
```
git clone https://github.com/<your-username>/NetArmageddon.git
```
# 2. Create feature branch
```
git checkout -b feature/awesome-feature
```
# 3. Install dev dependencies
```
pip install -r dev-requirements.txt
```
# 4. Commit changes with semantic messages
```
git commit -m "feat: add packet validation system"
```
# 5. Push and open PR
```
git push origin feature/awesome-feature
```

## License 📜
This project is licensed under [LICENSE](LICENSE)