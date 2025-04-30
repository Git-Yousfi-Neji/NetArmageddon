.PHONY: install format lint test docs

install:
	@pip install -r dev-requirements.txt
	@pre-commit install

format:
	@isort .
	@black .

lint:
	@flake8 netarmageddon tests
	@mypy netarmageddon tests
	@safety scan

test:
	@pytest -v --cov=netarmageddon --cov-report=term-missing

docs:
	@mkdocs build
	@mkdocs serve  # For live preview

ci-test:
	@pytest --cov=netarmageddon --cov-report=xml
