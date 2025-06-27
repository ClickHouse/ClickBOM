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

# Test 3: extract_sbom_from_wrapper with a temporary wrapped SBOM file
@test "extract_sbom_from_wrapper handles wrapped SBOM" {
    # Create a wrapped SBOM file
    local wrapped_sbom="$TEST_TEMP_DIR/wrapped_sbom.json"
    local extracted_sbom="$TEST_TEMP_DIR/extracted_sbom.json"
    
    cat > "$wrapped_sbom" << 'EOF'
{
    "status": "success",
    "sbom": {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "name": "test-component",
                "version": "1.0.0"
            }
        ]
    }
}
EOF

    # Test the extraction function
    run extract_sbom_from_wrapper "$wrapped_sbom" "$extracted_sbom"
    
    [ "$status" -eq 0 ]
    [ -f "$extracted_sbom" ]
    
    # Verify the extracted content is correct
    local extracted_format
    extracted_format=$(jq -r '.bomFormat' "$extracted_sbom")
    [ "$extracted_format" = "CycloneDX" ]
    
    # Verify the wrapper properties are gone
    run jq -e '.status' "$extracted_sbom"
    [ "$status" -ne 0 ]  # Should fail because .status shouldn't exist in extracted file
}

# Test 4: extract_sbom_from_wrapper handles unwrapped SBOM
@test "extract_sbom_from_wrapper handles non-wrapped SBOM" {
    # Create a non-wrapped SBOM file
    local normal_sbom="$TEST_TEMP_DIR/normal_sbom.json"
    local output_sbom="$TEST_TEMP_DIR/output_sbom.json"
    
    cat > "$normal_sbom" << 'EOF'
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": []
}
EOF

    # Test the extraction function (should just copy the file)
    run extract_sbom_from_wrapper "$normal_sbom" "$output_sbom"
    
    [ "$status" -eq 0 ]
    [ -f "$output_sbom" ]
    
    # Files should be identical
    run diff "$normal_sbom" "$output_sbom"
    [ "$status" -eq 0 ]
}