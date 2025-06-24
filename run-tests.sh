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
