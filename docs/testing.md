# Testing Strategy

## Test Types

| Test Level | Scope | Example |
|------------|-------|---------|
| Unit | Individual components | MAC generation |
| Integration | Module interactions | DHCP+ARP combined |
| Traffic    | PCAP capture flow     | `TrafficLogger` start/stop, duration, count limits |
| Safety | Rate limiting/validation | Invalid IP handling |

## Running Tests

```bash
# Full test suite with coverage
pytest -v --cov=netarmageddon --cov-report=term-missing

# Specific test module
pytest -v tests/test_dhcp.py

# Generate HTML coverage report
pytest --cov=netarmageddon --cov-report=html

# To run TrafficLogger unit tests:
pytest -v tests/test_traffic.py
```

## CI Pipeline
- Automatic test runs on PRs
- Coverage reporting to Codecov
- Security scanning with CodeQL
