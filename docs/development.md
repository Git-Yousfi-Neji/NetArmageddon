# Development Setup

## Environment Configuration

```bash
# Clone repository
git clone https://github.com/Git-Yousfi-Neji/NetArmageddon.git
cd NetArmageddon

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt -r dev-requirements.txt
```

## Contribution Guidelines

1. Create feature branch from `master`
2. Add tests for new functionality
3. Update documentation
4. Submit PR with description of changes
5. Ensure all tests pass (`pytest -v`)

## Code Standards
- PEP8 compliance
- Type hints for public methods
- Google-style docstrings
- 100-character line limit