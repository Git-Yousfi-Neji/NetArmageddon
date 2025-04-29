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
pip install -r requirements.txt
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

## Release Process
1. Update `__version__` in `netarmageddon/__init__.py`
2. Update `CHANGELOG.md`
3. Run full test suite: `pytest -v`
4. Commit changes: `git commit -am "Prepare vX.Y.Z"`
5. Tag release: `git tag -a vX.Y.Z -m "Version X.Y.Z"`
6. Push with tags: `git push && git push --tags`