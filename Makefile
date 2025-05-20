# ──────────────────────────────────────────────────────────────────────────────
# Top-Level Makefile for NetArmageddon
# ──────────────────────────────────────────────────────────────────────────────

GREEN  := \033[0;32m
BLUE   := \033[0;34m
YELLOW := \033[0;33m
RED    := \033[0;31m
RESET  := \033[0m

C_SRC_DIR = netarmageddon/core/traffic_c
COMPILE_COMMANDS = compile_commands.json

.PHONY: all c-clean c-build install format lint test docs_build docs_serve c-test help

all: clean c-clean install format c-format lint c-lint c-build test c-test docs_build

clean:
	@echo "$(YELLOW)→ Fixing ownership…$(RESET)"
	@sudo chown -R $(USER):$(USER) .
	@echo "$(GREEN)→→ DONE!$(RESET)"
	@echo "$(RED)→ Removing Python bytecode and __pycache__…"
	@find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	@find . -type f -name "*.py[co]" -delete
	@echo "$(GREEN)→→ DONE!$(RESET)"

	@echo "$(RED)→ Removing coverage and test reports…$(RESET)"
	@rm -f coverage.xml
	@rm -rf htmlcov
	@echo "$(GREEN)→→ DONE!$(RESET)"

	@echo "$(RED)→ Removing C build artifacts ($(C_SRC_DIR))…$(RESET)"
	@$(MAKE) -C $(C_SRC_DIR) clean
	@rm -f $(wildcard $(C_SRC_DIR)/$(COMPILE_COMMANDS))
	@echo "$(GREEN)→→ DONE!$(RESET)"

	@echo "$(RED)→ Removing documentation build…$(RESET)"
	@rm -rf site/
	@rm -rf .cache/
	@rm -rf netarmageddon/docs/_build/
	@echo "$(GREEN)→→ DONE!$(RESET)"

	@echo "$(RED)→ Removing packaging metadata…$(RESET)"
	@rm -rf netarmageddon.egg-info/
	@rm -f build/ dist/ *.egg-info
	@echo "$(GREEN)→→ DONE!$(RESET)"

	@echo "$(RED)→ Removing virtualenvs and installers…$(RESET)"
	@rm -rf venv/ .venv/         # if you use these directories
	@echo "$(GREEN)→→ DONE!$(RESET)"

	@echo "$(GREEN)→→→ Clean complete.$(RESET)"

c-clean:
	@echo "$(RED)→ Cleaning C traffic logger…$(RESET)"
	@$(MAKE) -C $(C_SRC_DIR) clean
	@echo "$(GREEN)→→ DONE!$(RESET)"

# Generate compile_commands.json needed for c-lint
compile_commands:
	@echo "$(BLUE)→ Generating compile_commands.json…$(RESET)"
	@bear --append -- make -C $(C_SRC_DIR)
	@mv $(COMPILE_COMMANDS) $(C_SRC_DIR)/$(COMPILE_COMMANDS)
	@echo "$(GREEN)→→ DONE!$(RESET)"

c-build: compile_commands
	@echo "$(GREEN)→ Building C traffic logger…$(RESET)"
	@$(MAKE) -C $(C_SRC_DIR)
	@echo "$(GREEN)→→ DONE!$(RESET)"

install:
	@echo "$(BLUE)→ Installing dependencies…$(RESET)"
	@sudo apt-get update
	@sudo python3 -m pip install --upgrade --ignore-installed pip
	@sudo pip install --ignore-installed -r requirements.txt -r dev-requirements.txt
	@sudo apt-get install -y libpcap-dev
	@sudo apt-get install -y clang-format
	@sudo apt-get install -y clang-tidy
	@sudo apt-get install -y bear
	@sudo apt-get install -y check
	@sudo apt-get install -y libnl-3-dev
	@sudo apt-get install -y libnl-genl-3-dev
	@sudo apt-get install -y linux-headers-$(uname -r)
	@pre-commit install
	@echo "$(GREEN)→→ DONE!$(RESET)"

format:
	@echo "$(BLUE)→ Running formatters…$(RESET)"
	@isort .
	@black .
	@echo "$(GREEN)→→ DONE!$(RESET)"

c-format:
	@echo "$(BLUE)→ Formatting C files with clang-format…$(RESET)"
	@$(MAKE) -C $(C_SRC_DIR) format
	@echo "$(GREEN)→→ DONE!$(RESET)"

lint:
	@echo "$(BLUE)→ Running linters…$(RESET)"
	@flake8 netarmageddon tests
	@mypy netarmageddon tests
	@echo "$(GREEN)→→ DONE!$(RESET)"

c-lint: c-clean c-build
	@echo "$(BLUE)→ Linting C files with clang-tidy…$(RESET)"
	@$(MAKE) -C $(C_SRC_DIR) lint
	@echo "$(GREEN)→→ DONE!$(RESET)"

test: c-clean c-build
	@echo "$(GREEN)→ Running Python tests…$(RESET)"
	@pytest -v --cov=netarmageddon --cov-report=term-missing
	@echo "$(GREEN)→→ DONE!$(RESET)"

c-test: c-clean c-build
	@echo "$(GREEN)→ Running C tests…$(RESET)"
	@sudo $(MAKE) -C $(C_SRC_DIR) test
	@echo "$(GREEN)→→ DONE!$(RESET)"

docs_build:
	@echo "$(BLUE)→ Building docs…$(RESET)"
	@mkdocs build
	@echo "$(GREEN)→→ DONE!$(RESET)"

docs_serve:
	@echo "$(BLUE)→ Serving docs locally…$(RESET)"
	@mkdocs serve
	@echo "$(GREEN)→→ DONE!$(RESET)"

help:
	@echo "$(GREEN)Available targets:$(RESET)"
	@echo "  $(YELLOW)all$(RESET):         Run c-clean, c-build, install, format, lint, test, docs_build"
	@echo "  $(RED)clean$(RESET):    Clean everything"
	@echo "  $(RED)c-clean$(RESET):     Clean C build artifacts"
	@echo "  $(YELLOW)c-build$(RESET):   Build C traffic-logger"
	@echo "  $(YELLOW)install$(RESET):     Install Python & system deps"
	@echo "  $(YELLOW)format$(RESET):      Reflow source code—sort imports (isort) and auto-format (black)"
	@echo "  $(YELLOW)c-format$(RESET):      Same as format but this is for C"
	@echo "  $(YELLOW)lint$(RESET):        Validate code—style checks (flake8), type checks (mypy), and dependency security (safety)"
	@echo "  $(YELLOW)c-lint$(RESET):        Same as lint but this is for C"
	@echo "  $(YELLOW)test$(RESET):        Clean & run pytest"
	@echo "  $(YELLOW)c-test$(RESET):        Clean & run C tests"
	@echo "  $(YELLOW)docs_build$(RESET):  Build documentation"
	@echo "  $(YELLOW)docs_serve$(RESET):  Serve docs locally"
	@echo "  $(GREEN)help$(RESET):        Show this help message"
