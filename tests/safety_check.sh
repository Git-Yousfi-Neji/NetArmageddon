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
test_rate_limit() {
    python -m netarmageddon dhcp -i lo -n 101 2>&1 | \
    grep -q "exceeds safety limit"
}

test_invalid_interface() {
    python -m netarmageddon dhcp -i invalid_interface -n 10 2>&1 | \
    grep -q "not found"
}

test_invalid_ip_format() {
    python -m netarmageddon arp -i lo -b 192.168.1 -n 10 2>&1 | \
    grep -q "Invalid base IP"
}

# Main execution
header
test_case "DHCP Rate Limiting" test_rate_limit
test_case "Invalid Interface Handling" test_invalid_interface
test_case "Invalid IP Format Validation" test_invalid_ip_format
footer