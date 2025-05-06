.PHONY: install format lint test docs ci-tests

install:
	@pip install -r requirements.txt -r dev-requirements.txt -e .
	@sudo apt-get install libpcap-dev
	@pre-commit install

format:
	@isort .
	@black .

lint:
	@flake8 netarmageddon tests
	@mypy netarmageddon tests
	@safety scan || echo "Safety scan skipped - add SAFETY_API_KEY for full check"

test:
	@pytest -v --cov=netarmageddon --cov-report=term-missing

docs:
	@mkdocs build
	@mkdocs serve  # For live preview

ci-test:
	@pytest --cov=netarmageddon --cov-report=xml
