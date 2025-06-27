#!/usr/bin/env bats

# test/advanced_tests.bats
# Advanced BATS tests for entrypoint.sh

# Setup function runs before each test
setup() {
    # Source the script functions without executing main
    source <(sed '/^# Run main function/,$d' entrypoint.sh)
    
    # Create a temporary directory for this test session
    # BATS_TEST_TMPDIR is provided by BATS automatically
    export TEST_TEMP_DIR="$BATS_TEST_TMPDIR"
    
    # Set up basic required environment variables
    export AWS_ACCESS_KEY_ID="test-key"
    export AWS_SECRET_ACCESS_KEY="test-secret"
    export S3_BUCKET="test-bucket"
    export REPOSITORY="test-owner/test-repo"
    export GITHUB_TOKEN="test-token"
    
    # Create mock directory in PATH (for mocking external commands)
    export MOCK_DIR="$BATS_TEST_TMPDIR/mocks"
    mkdir -p "$MOCK_DIR"
    
    # Prepend mock directory to PATH so our mocks are found first
    export PATH="$MOCK_DIR:$PATH"
}

# Teardown function runs after each test
teardown() {
    # Clean up environment variables
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY S3_BUCKET REPOSITORY GITHUB_TOKEN
    unset TEST_TEMP_DIR MOCK_DIR
    
    # BATS automatically cleans up BATS_TEST_TMPDIR, but we can do extra cleanup if needed
}

# ============================================================================
# TESTS WITH TEMPORARY FILES
# ============================================================================

# Test 1: detect_sbom_format with a temporary CycloneDX SBOM file
@test "detect_sbom_format works with temporary CycloneDX file" {
    # Create a temporary CycloneDX SBOM file
    local test_sbom="$TEST_TEMP_DIR/cyclonedx_test.json"
    cat > "$test_sbom" << 'EOF'
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.6", 
    "serialNumber": "urn:uuid:test-123",
    "metadata": {
        "component": {
            "name": "test-component",
            "version": "1.0.0"
        }
    },
    "components": []
}
EOF

    # Verify the file was created
    [ -f "$test_sbom" ]
    [ -s "$test_sbom" ]  # File exists and is not empty
    
    # Test the function
    run detect_sbom_format "$test_sbom"
    
    [ "$status" -eq 0 ]
    [ "$output" = "cyclonedx" ]
}

# Test 2: detect_sbom_format with a temporary SPDX SBOM file
@test "detect_sbom_format works with temporary SPDX file" {
    # Create a temporary SPDX SBOM file
    local test_sbom="$TEST_TEMP_DIR/spdx_test.json"
    
    cat > "$test_sbom" << 'EOF'
{
    "spdxVersion": "SPDX-2.2",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "test-document",
    "documentNamespace": "https://example.com/test",
    "packages": [
        {
            "SPDXID": "SPDXRef-Package",
            "name": "test-package",
            "versionInfo": "1.0.0"
        }
    ]
}
EOF

    # Verify the file was created correctly
    [ -f "$test_sbom" ]
    [ -s "$test_sbom" ]
    
    # Verify it's valid JSON
    run jq . "$test_sbom"
    [ "$status" -eq 0 ]
    
    # Test the function
    run detect_sbom_format "$test_sbom"
    
    [ "$status" -eq 0 ]
    [ "$output" = "spdxjson" ]
}
