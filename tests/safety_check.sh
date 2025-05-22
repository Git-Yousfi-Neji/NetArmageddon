#!/bin/bash

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0

header() {
    echo -e "${YELLOW}"
    echo "------------------------------------------------"
    echo " NetArmageddon Safety Test Suite "
    echo "------------------------------------------------"
    echo -e "${NC}"
}

test_case() {
    local test_name="$1"
    shift
    echo -e "${CYAN}▶ Running test: ${test_name}${NC}"

    if "$@"; then
        echo -e "${GREEN}✔ Success: ${test_name}${NC}\n"
        ((PASSED++))
    else
        echo -e "${RED}✖ Failed: ${test_name}${NC}\n"
        ((FAILED++))
    fi
}

footer() {
    echo -e "${YELLOW}"
    echo "------------------------------------------------"
    echo -e "Test Results:"
    echo -e "${GREEN}Passed: ${PASSED}${NC}"
    echo -e "${RED}Failed: ${FAILED}${NC}"
    echo -e "${YELLOW}------------------------------------------------${NC}"

    exit $((FAILED > 0 ? 1 : 0))
}

# Test functions
test_dhcp() {
    pytest --verbose --color=yes --code-highlight=yes tests/test_dhcp.py
}

test_arp() {
    pytest --verbose --color=yes --code-highlight=yes tests/test_arp.py
}

test_traffic() {
    pytest --verbose --color=yes --code-highlight=yes tests/test_traffic.py
}

test_deauth() {
    pytest --verbose --color=yes --code-highlight=yes tests/test_deauth.py
}

# Main execution
header
test_case "DHCP" test_dhcp
test_case "DHCP" test_arp
test_case "DHCP" test_traffic
test_case "DHCP" test_deauth
footer
