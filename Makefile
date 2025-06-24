.PHONY: test test-verbose clean help

# Default target
help:
	@echo "Available targets:"
	@echo "  test         - Run all tests"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  clean        - Clean test artifacts"
	@echo "  help         - Show this help"

# Run tests
test:
	@echo "Running BATS tests..."
	@bats test/*.bats

# Run tests with verbose output
test-verbose:
	@echo "Running BATS tests (verbose)..."
	@bats --verbose-run test/*.bats

# Clean test artifacts
clean:
	@echo "Cleaning test artifacts..."
	@find test -name "*.tmp" -delete 2>/dev/null || true
	@rm -rf test/tmp 2>/dev/null || true
