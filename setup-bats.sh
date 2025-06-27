#!/bin/bash

# setup-bats.sh - Install and configure BATS for testing

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}Setting up BATS testing framework...${NC}"

# Create test directory structure
mkdir -p test

# Check if bats is already installed
if command -v bats >/dev/null 2>&1; then
    echo -e "${GREEN}BATS is already installed!${NC}"
    bats --version
else
    echo -e "${YELLOW}Installing BATS...${NC}"
    
    # Install BATS based on the operating system
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux - try different package managers
        if command -v apt-get >/dev/null 2>&1; then
            echo "Installing via apt..."
            sudo apt-get update && sudo apt-get install -y bats
        elif command -v yum >/dev/null 2>&1; then
            echo "Installing via yum..."
            sudo yum install -y bats
        elif command -v dnf >/dev/null 2>&1; then
            echo "Installing via dnf..."
            sudo dnf install -y bats
        else
            echo "Installing from source..."
            git clone https://github.com/bats-core/bats-core.git /tmp/bats-core
            cd /tmp/bats-core
            sudo ./install.sh /usr/local
            cd -
            rm -rf /tmp/bats-core
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew >/dev/null 2>&1; then
            echo "Installing via Homebrew..."
            brew install bats-core
        else
            echo "Please install Homebrew first, then run: brew install bats-core"
            exit 1
        fi
    else
        echo "Unsupported OS. Please install BATS manually."
        echo "Visit: https://github.com/bats-core/bats-core"
        exit 1
    fi
fi

# Verify installation
if command -v bats >/dev/null 2>&1; then
    echo -e "${GREEN}BATS installation verified!${NC}"
    bats --version
else
    echo "BATS installation failed. Please install manually."
    exit 1
fi

# Create a basic test file if it doesn't exist
if [[ ! -f "test/entrypoint.bats" ]]; then
    echo -e "${BLUE}Creating basic test file...${NC}"
    # The test file content would go here, but since we already created it above,
    # we'll just create a placeholder or copy the content
    cat > test/entrypoint.bats << 'EOF'
#!/usr/bin/env bats

# Basic test to verify BATS is working
@test "basic test - addition" {
    result="$((2 + 2))"
    [ "$result" -eq 4 ]
}

# Add more tests here...
EOF
fi

# Create a test runner script only if it doesn't exist
if [[ ! -f "run-tests.sh" ]]; then
    # Create a test runner script
    cat > run-tests.sh << 'EOF'
#!/bin/bash

# run-tests.sh - Test runner script

set -euo pipefail

echo "Running BATS tests..."

# Run all tests in the test directory
if bats test/*.bats; then
    echo "✅ All tests passed!"
else
    echo "❌ Some tests failed!"
    exit 1
fi
EOF

    chmod +x run-tests.sh
else
    echo -e "${YELLOW}Test runner script already exists: run-tests.sh${NC}"
fi
