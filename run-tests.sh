#!/bin/bash

# run-tests.sh - Enhanced test runner for your BATS tests

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print usage
usage() {
    echo "Usage: $0 [OPTIONS] [TEST_FILE]"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help message"
    echo "  -v, --verbose    Run tests with verbose output"
    echo "  -s, --simple     Run only simple tests"
    echo "  -a, --advanced   Run only advanced tests"
    echo "  -f, --filter     Filter tests by pattern"
    echo "  --setup          Check test setup and dependencies"
    echo "  --list           List available test files"
    echo ""
    echo "Examples:"
    echo "  $0                          # Run all tests"
    echo "  $0 -s                       # Run simple tests only"
    echo "  $0 -a                       # Run advanced tests only"
    echo "  $0 -v                       # Run with verbose output"
    echo "  $0 -f 'log_info'            # Run tests matching 'log_info'"
    echo "  $0 test/simple_start.bats   # Run specific test file"
}

# Check if BATS is installed
check_bats() {
    if ! command -v bats >/dev/null 2>&1; then
        echo -e "${RED}❌ BATS is not installed!${NC}"
        echo "Run ./setup-bats.sh to install BATS first."
        exit 1
    fi
    
    echo -e "${GREEN}✅ BATS is installed:${NC} $(bats --version)"
}

# Check if required dependencies are available
check_dependencies() {
    echo -e "${BLUE}🔍 Checking dependencies...${NC}"
    
    local missing_deps=()
    
    # Check for jq (used by your script)
    if ! command -v jq >/dev/null 2>&1; then
        missing_deps+=("jq")
    fi
    
    # Check for basic Unix tools
    for tool in sed awk grep; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_deps+=("$tool")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Missing dependencies:${NC} ${missing_deps[*]}"
        echo "Install them with your package manager (e.g., apt install jq)"
        return 1
    else
        echo -e "${GREEN}✅ All dependencies available${NC}"
        return 0
    fi
}

# List available test files
list_tests() {
    echo -e "${BLUE}📋 Available test files:${NC}"
    
    if [[ -d test ]]; then
        local test_files
        test_files=$(find test -name "*.bats" 2>/dev/null || true)
        
        if [[ -n "$test_files" ]]; then
            while IFS= read -r file; do
                local test_count
                test_count=$(grep -c "^@test" "$file" 2>/dev/null || echo "0")
                echo "  📁 $file ($test_count tests)"
                
                # Show test names
                if [[ "$test_count" -gt 0 ]]; then
                    grep "^@test" "$file" | sed 's/@test /    - /' | sed 's/ {$//'
                fi
                echo ""
            done <<< "$test_files"
        else
            echo "  (No test files found in test/ directory)"
        fi
    else
        echo "  (No test/ directory found)"
    fi
}

# Run setup checks
setup_check() {
    echo -e "${BLUE}🔧 Checking test setup...${NC}"
    
    check_bats
    check_dependencies
    
    # Check if entrypoint.sh exists and is readable
    if [[ -f "entrypoint.sh" ]]; then
        echo -e "${GREEN}✅ entrypoint.sh found${NC}"
        
        # Check if it's executable
        if [[ -x "entrypoint.sh" ]]; then
            echo -e "${GREEN}✅ entrypoint.sh is executable${NC}"
        else
            echo -e "${YELLOW}⚠️  entrypoint.sh is not executable${NC}"
            echo "Run: chmod +x entrypoint.sh"
        fi
        
        # Basic syntax check
        if bash -n entrypoint.sh; then
            echo -e "${GREEN}✅ entrypoint.sh syntax is valid${NC}"
        else
            echo -e "${RED}❌ entrypoint.sh has syntax errors${NC}"
            return 1
        fi
    else
        echo -e "${RED}❌ entrypoint.sh not found${NC}"
        echo "Make sure you're running this from the directory containing entrypoint.sh"
        return 1
    fi
    
    # Check test directory
    if [[ -d test ]]; then
        echo -e "${GREEN}✅ test/ directory found${NC}"
        local bats_files
        bats_files=$(find test -name "*.bats" | wc -l)
        echo -e "${GREEN}✅ Found $bats_files BATS test files${NC}"
    else
        echo -e "${YELLOW}⚠️  test/ directory not found${NC}"
        echo "Create it with: mkdir test"
    fi
    
    echo -e "${GREEN}🎉 Setup check complete!${NC}"
}

# Run BATS tests with options
run_bats() {
    local bats_args=()
    local test_files=()
    
    # Add verbose flag if requested
    if [[ "${VERBOSE:-false}" == "true" ]]; then
        bats_args+=("--verbose-run")
    fi
    
    # Add filter if provided
    if [[ -n "${FILTER:-}" ]]; then
        bats_args+=("--filter" "$FILTER")
    fi
    
    # Determine which tests to run
    if [[ "${SIMPLE_ONLY:-false}" == "true" ]]; then
        test_files=("test/simple_start.bats")
    elif [[ "${ADVANCED_ONLY:-false}" == "true" ]]; then
        test_files=("test/advanced_tests.bats")
    elif [[ -n "${SPECIFIC_FILE:-}" ]]; then
        test_files=("$SPECIFIC_FILE")
    else
        # Run all test files
        if [[ -d test ]]; then
            mapfile -t test_files < <(find test -name "*.bats" | sort)
        fi
    fi
    
    # Check if we have any test files
    if [[ ${#test_files[@]} -eq 0 ]]; then
        echo -e "${YELLOW}⚠️  No test files found to run${NC}"
        echo "Available options:"
        echo "  - Create test/simple_start.bats for simple tests"
        echo "  - Create test/advanced_tests.bats for advanced tests"
        echo "  - Run ./setup-bats.sh to set up basic test structure"
        return 1
    fi
    
    # Run the tests
    echo -e "${BLUE}🧪 Running BATS tests...${NC}"
    echo "Test files: ${test_files[*]}"
    echo "BATS args: ${bats_args[*]}"
    echo ""
    
    local exit_code=0
    local failed_files=()
    
    for test_file in "${test_files[@]}"; do
        if [[ -f "$test_file" ]]; then
            echo -e "${BLUE}📝 Running $test_file...${NC}"
            if bats "${bats_args[@]}" "$test_file"; then
                echo -e "${GREEN}✅ $test_file passed${NC}"
            else
                echo -e "${RED}❌ $test_file failed${NC}"
                failed_files+=("$test_file")
                exit_code=1
            fi
            echo ""
        else
            echo -e "${YELLOW}⚠️  Test file not found: $test_file${NC}"
            exit_code=1
        fi
    done
    
    # Summary
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}🎉 All tests passed!${NC}"
    else
        echo -e "${RED}💥 Some tests failed:${NC}"
        for file in "${failed_files[@]}"; do
            echo "  - $file"
        done
        echo ""
        echo -e "${YELLOW}💡 Debugging tips:${NC}"
        echo "  - Run with -v for verbose output"
        echo "  - Check test setup with --setup"
        echo "  - Run individual test files to isolate issues"
    fi
    
    return $exit_code
}

# Parse command line arguments
VERBOSE=false
SIMPLE_ONLY=false
ADVANCED_ONLY=false
FILTER=""
SPECIFIC_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -s|--simple)
            SIMPLE_ONLY=true
            shift
            ;;
        -a|--advanced)
            ADVANCED_ONLY=true
            shift
            ;;
        -f|--filter)
            FILTER="$2"
            shift 2
            ;;
        --setup)
            setup_check
            exit $?
            ;;
        --list)
            list_tests
            exit 0
            ;;
        *.bats)
            SPECIFIC_FILE="$1"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Check basic setup first
    check_bats
    
    # Run the tests
    run_bats
fi
