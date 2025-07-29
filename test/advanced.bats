#!/usr/bin/env bats

# test/advanced_tests.bats
# Advanced BATS tests for entrypoint.sh

# Setup function runs before each test
setup() {
    # Get the directory where this test is located
    export BATS_TEST_DIRNAME="$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)"
    export PROJECT_ROOT="$(dirname "$BATS_TEST_DIRNAME")"
    
    # Create a temporary test script that sources functions without executing main
    export TEST_SCRIPT="$BATS_TEST_TMPDIR/test_entrypoint.sh"
    
    # Extract only the functions from entrypoint.sh (everything before main function call)
    sed '/^# Run main function/,$d' "$PROJECT_ROOT/entrypoint.sh" > "$TEST_SCRIPT"
    
    # Fix the lib/sanitize.sh source path in the extracted script
    sed -i "s|source \"\$SCRIPT_DIR/lib/sanitize.sh\"|source \"$PROJECT_ROOT/lib/sanitize.sh\"|" "$TEST_SCRIPT"
    
    # Source the functions
    source "$TEST_SCRIPT"
    
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

# ============================================================================
# TESTS WITH COMMAND MOCKING
# ============================================================================

# Test 5: upload_to_s3 with mocked aws command
@test "upload_to_s3 calls aws s3 cp with correct parameters" {
    # Create a mock aws command that logs what it was called with
    cat > "$MOCK_DIR/aws" << 'EOF'
#!/bin/bash
# Mock aws command - just log the arguments and succeed
echo "aws called with: $*" >> "$BATS_TEST_TMPDIR/aws_calls.log"
exit 0
EOF
    chmod +x "$MOCK_DIR/aws"
    
    # Create a test file to upload
    local test_file="$TEST_TEMP_DIR/test_sbom.json"
    echo '{"bomFormat": "CycloneDX"}' > "$test_file"
    
    # Test the upload function
    run upload_to_s3 "$test_file" "my-bucket" "path/to/sbom.json"
    
    [ "$status" -eq 0 ]
    
    # Verify aws was called with correct parameters
    [ -f "$BATS_TEST_TMPDIR/aws_calls.log" ]
    local aws_call
    aws_call=$(cat "$BATS_TEST_TMPDIR/aws_calls.log")
    
    [[ "$aws_call" == *"s3 cp"* ]]
    [[ "$aws_call" == *"$test_file"* ]]
    [[ "$aws_call" == *"s3://my-bucket/path/to/sbom.json"* ]]
    [[ "$aws_call" == *"--content-type"* ]]
    [[ "$aws_call" == *"application/json"* ]]
}

# Test 6: upload_to_s3 handles aws command failure
@test "upload_to_s3 handles aws command failure" {
    # Create a mock aws command that fails
    cat > "$MOCK_DIR/aws" << 'EOF'
#!/bin/bash
echo "AWS Error: Access denied" >&2
exit 1
EOF
    chmod +x "$MOCK_DIR/aws"
    
    # Create a test file
    local test_file="$TEST_TEMP_DIR/test_sbom.json"
    echo '{"bomFormat": "CycloneDX"}' > "$test_file"
    
    # Test the upload function - should fail
    run upload_to_s3 "$test_file" "my-bucket" "path/to/sbom.json"
    
    [ "$status" -eq 1 ]
    [[ "$output" == *"Failed to upload SBOM to S3"* ]]
}

# Test 7: download_sbom with mocked curl command
@test "download_sbom calls curl with correct GitHub API parameters" {
    # Create a mock curl command
    cat > "$MOCK_DIR/curl" << 'EOF'
#!/bin/bash
# Mock curl command - log the call and return fake SBOM data
echo "curl called with: $*" >> "$BATS_TEST_TMPDIR/curl_calls.log"

# Check if this is the GitHub API call we expect
if [[ "$*" == *"api.github.com/repos"* ]] && [[ "$*" == *"dependency-graph/sbom"* ]]; then
    # Find the output file from the arguments
    local output_file=""
    local next_is_output=false
    for arg in "$@"; do
        if [[ "$next_is_output" == "true" ]]; then
            output_file="$arg"
            break
        fi
        if [[ "$arg" == "-o" ]]; then
            next_is_output=true
        fi
    done
    
    # Write fake SBOM data to the output file
    if [[ -n "$output_file" ]]; then
        cat > "$output_file" << 'SBOM_EOF'
{
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
SBOM_EOF
    fi
    exit 0
else
    exit 1
fi
EOF
    chmod +x "$MOCK_DIR/curl"
    
    # Test the download function
    local output_file="$TEST_TEMP_DIR/downloaded_sbom.json"
    run download_sbom "owner/repo" "$output_file"
    
    [ "$status" -eq 0 ]
    [ -f "$output_file" ]
    
    # Verify curl was called correctly
    [ -f "$BATS_TEST_TMPDIR/curl_calls.log" ]
    local curl_call
    curl_call=$(cat "$BATS_TEST_TMPDIR/curl_calls.log")
    
    [[ "$curl_call" == *"api.github.com/repos/owner/repo/dependency-graph/sbom"* ]]
    [[ "$curl_call" == *"Authorization: Bearer $GITHUB_TOKEN"* ]]
    [[ "$curl_call" == *"-o $output_file"* ]]
    
    # Verify the downloaded file is valid JSON
    run jq . "$output_file"  
    [ "$status" -eq 0 ]
}

# Test 8: download_sbom handles curl failure
@test "download_sbom handles curl failure" {
    # Create a mock curl command that fails
    cat > "$MOCK_DIR/curl" << 'EOF'
#!/bin/bash
echo "curl: (7) Failed to connect to api.github.com" >&2
exit 7
EOF
    chmod +x "$MOCK_DIR/curl"
    
    # Test the download function - should fail
    local output_file="$TEST_TEMP_DIR/failed_download.json"
    run download_sbom "owner/repo" "$output_file"
    
    [ "$status" -eq 1 ]
    [[ "$output" == *"Failed to download SBOM file"* ]]
}

# Test 9: mock jq command for testing JSON processing
@test "mock jq command for testing JSON processing" {
    # Create a mock jq that returns predictable output
    cat > "$MOCK_DIR/jq" << 'EOF'
#!/bin/bash
# Mock jq command
echo "jq called with: $*" >> "$BATS_TEST_TMPDIR/jq_calls.log"

# Handle different jq operations
case "$*" in
    *".bomFormat"*)
        echo "CycloneDX"
        ;;
    *".spdxVersion"*)
        echo "SPDX-2.2"
        ;;
    *". | empty"*)
        # JSON validation - just succeed
        exit 0
        ;;
    *)
        # Default - just succeed
        exit 0
        ;;
esac
EOF
    chmod +x "$MOCK_DIR/jq"
    
    # Create a test file
    local test_file="$TEST_TEMP_DIR/test.json"
    echo '{"bomFormat": "CycloneDX"}' > "$test_file"
    
    # Test detect_sbom_format with our mock
    run detect_sbom_format "$test_file"
    
    [ "$status" -eq 0 ]
    [ "$output" = "cyclonedx" ]
    
    # Verify jq was called
    [ -f "$BATS_TEST_TMPDIR/jq_calls.log" ]
    local jq_call
    jq_call=$(cat "$BATS_TEST_TMPDIR/jq_calls.log")
    [[ "$jq_call" == *".bomFormat"* ]]
}

# ============================================================================
# COMPLEX SCENARIOS - COMBINING MOCKING AND TEMP FILES
# ============================================================================

# Test 10: full workflow simulation with mocks and temp files
@test "full workflow simulation with mocks and temp files" {
    # Set up multiple mocks
    
    # Mock curl for downloading
    cat > "$MOCK_DIR/curl" << 'EOF'
#!/bin/bash
if [[ "$*" == *"dependency-graph/sbom"* ]]; then
    # Find output file
    local output_file=""
    local next_is_output=false
    for arg in "$@"; do
        if [[ "$next_is_output" == "true" ]]; then
            output_file="$arg"
            break
        fi
        if [[ "$arg" == "-o" ]]; then
            next_is_output=true
        fi
    done
    
    # Create a realistic wrapped SBOM
    cat > "$output_file" << 'SBOM_EOF'
{
    "sbom": {
        "spdxVersion": "SPDX-2.2",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test-repo",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-test",
                "name": "lodash",
                "versionInfo": "4.17.21",
                "licenseConcluded": "MIT"
            }
        ]
    }
}
SBOM_EOF
    exit 0
fi
exit 1
EOF
    chmod +x "$MOCK_DIR/curl"
    
    # Mock cyclonedx convert command
    cat > "$MOCK_DIR/cyclonedx" << 'EOF'
#!/bin/bash
# Mock cyclonedx convert
echo "cyclonedx called with: $*" >> "$BATS_TEST_TMPDIR/cyclonedx_calls.log"

# Find input and output files - handle --flag value format
input_file=""
output_file=""
i=1
while [[ $i -le $# ]]; do
    case "${!i}" in
        --input-file)
            ((i++))
            input_file="${!i}"
            ;;
        --output-file)
            ((i++))
            output_file="${!i}"
            ;;
    esac
    ((i++))
done

echo "Mock cyclonedx: input=$input_file, output=$output_file" >> "$BATS_TEST_TMPDIR/cyclonedx_calls.log"

# Convert SPDX to CycloneDX (simplified simulation)
if [[ -n "$output_file" ]]; then
    cat > "$output_file" << 'CONVERTED_EOF'
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {
            "name": "lodash",
            "version": "4.17.21",
            "licenses": [
                {
                    "license": {
                        "id": "MIT"
                    }
                }
            ]
        }
    ]
}
CONVERTED_EOF
    echo "Mock cyclonedx: Created output file $output_file" >> "$BATS_TEST_TMPDIR/cyclonedx_calls.log"
else
    echo "Mock cyclonedx: No output file specified!" >> "$BATS_TEST_TMPDIR/cyclonedx_calls.log"
    exit 1
fi
exit 0
EOF
    chmod +x "$MOCK_DIR/cyclonedx"
    
    # Mock aws s3 cp
    cat > "$MOCK_DIR/aws" << 'EOF'
#!/bin/bash
echo "aws s3 cp successful" >> "$BATS_TEST_TMPDIR/aws_calls.log"
exit 0
EOF
    chmod +x "$MOCK_DIR/aws"
    
    # Set up test environment
    export SBOM_FORMAT="cyclonedx"
    export SBOM_SOURCE="github"
    
    # Create temporary files for the workflow
    local original_sbom="$TEST_TEMP_DIR/original.json"
    local extracted_sbom="$TEST_TEMP_DIR/extracted.json"
    local converted_sbom="$TEST_TEMP_DIR/converted.json"
    
    # Test the workflow steps
    
    # Step 1: Download SBOM
    run download_sbom "test/repo" "$original_sbom"
    [ "$status" -eq 0 ]
    [ -f "$original_sbom" ]
    
    # Step 2: Extract from wrapper
    run extract_sbom_from_wrapper "$original_sbom" "$extracted_sbom"
    [ "$status" -eq 0 ]
    [ -f "$extracted_sbom" ]
    
    # Step 3: Detect format
    run detect_sbom_format "$extracted_sbom"
    [ "$status" -eq 0 ]
    [ "$output" = "spdxjson" ]
    
    # Step 4: Convert format
    run convert_sbom "$extracted_sbom" "$converted_sbom" "spdxjson" "cyclonedx"
    [ "$status" -eq 0 ]
    [ -f "$converted_sbom" ]
    
    # Step 5: Upload to S3
    run upload_to_s3 "$converted_sbom" "test-bucket" "test-key.json"
    [ "$status" -eq 0 ]
    
    # Verify all our mocks were called
    [ -f "$BATS_TEST_TMPDIR/cyclonedx_calls.log" ]
    [ -f "$BATS_TEST_TMPDIR/aws_calls.log" ]
    
    # Verify final file format
    local final_format
    # Use real jq here since we want to actually check the file
    final_format=$(jq -r '.bomFormat' "$converted_sbom")
    [ "$final_format" = "CycloneDX" ]
}

# ============================================================================
# SANITIZE_INPUTS INTEGRATION TESTS
# ============================================================================

# Test 11: sanitize_inputs processes repository correctly
@test "sanitize_inputs processes repository correctly" {
    export REPOSITORY="test-org/test-repo"
    
    run sanitize_inputs
    [ "$status" -eq 0 ]
    [[ "$output" == *"Input sanitization completed successfully"* ]]
}

# Test 12: sanitize_inputs processes Mend email correctly
@test "sanitize_inputs processes Mend email correctly" {
    export SBOM_SOURCE="mend"
    export MEND_EMAIL="test@example.com"
    export MEND_ORG_UUID="123e4567-e89b-12d3-a456-426614174000"
    export MEND_USER_KEY="test-key"
    export MEND_BASE_URL="https://api.mend.io"
    export MEND_PROJECT_UUID="123e4567-e89b-12d3-a456-426614174000"
    
    run sanitize_inputs
    [ "$status" -eq 0 ]
    [[ "$output" == *"Input sanitization completed successfully"* ]]
}

# Test 13: sanitize_inputs processes S3 bucket correctly
@test "sanitize_inputs processes S3 bucket correctly" {
    export S3_BUCKET="My-Test-Bucket"
    
    run sanitize_inputs
    [ "$status" -eq 0 ]
    [[ "$output" == *"Input sanitization completed successfully"* ]]
}

# Test 14: sanitize_inputs validates SBOM_SOURCE enum
@test "sanitize_inputs validates SBOM_SOURCE enum" {
    export SBOM_SOURCE="invalid-source"
    
    run sanitize_inputs
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid SBOM_SOURCE: invalid-source"* ]]
}

# Test 15: sanitize_inputs validates SBOM_FORMAT enum
@test "sanitize_inputs validates SBOM_FORMAT enum" {
    export SBOM_FORMAT="invalid-format"
    
    run sanitize_inputs
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid SBOM_FORMAT: invalid-format"* ]]
}

# Test 16: sanitize_inputs validates MERGE boolean
@test "sanitize_inputs validates MERGE boolean" {
    export MERGE="maybe"
    
    run sanitize_inputs
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid MERGE value: maybe"* ]]
}

# Test 17: sanitize_inputs processes include patterns correctly
@test "sanitize_inputs processes include patterns correctly" {
    export INCLUDE=" *.json , test*.txt , file.log "
    
    run sanitize_inputs
    [ "$status" -eq 0 ]
    [[ "$output" == *"Input sanitization completed successfully"* ]]
}

# Test 18: sanitize_inputs processes exclude patterns correctly
@test "sanitize_inputs processes exclude patterns correctly" {
    export EXCLUDE="*-dev.json,*-test.json"
    
    run sanitize_inputs
    [ "$status" -eq 0 ]
    [[ "$output" == *"Input sanitization completed successfully"* ]]
}

# Test 19: sanitize_inputs processes ClickHouse URL correctly
@test "sanitize_inputs processes ClickHouse URL correctly" {
    export CLICKHOUSE_URL="https://clickhouse.example.com:8443"
    
    run sanitize_inputs
    [ "$status" -eq 0 ]
    [[ "$output" == *"Input sanitization completed successfully"* ]]
}

# Test 20: sanitize_inputs processes multiple Mend project UUIDs
@test "sanitize_inputs processes multiple Mend project UUIDs" {
    export MEND_PROJECT_UUIDS="123e4567-e89b-12d3-a456-426614174000, 456e7890-e89b-12d3-a456-426614174000"
    
    run sanitize_inputs
    [ "$status" -eq 0 ]
    [[ "$output" == *"Input sanitization completed successfully"* ]]
}

# Test 21: sanitize_inputs processes numeric values with validation
@test "sanitize_inputs processes numeric values with validation" {
    export MEND_MAX_WAIT_TIME="1800"
    export MEND_POLL_INTERVAL="30"
    
    run sanitize_inputs
    [ "$status" -eq 0 ]
    [[ "$output" == *"Input sanitization completed successfully"* ]]
}

# Test 22: sanitize_inputs rejects invalid numeric values
@test "sanitize_inputs rejects invalid numeric values" {
    export MEND_MAX_WAIT_TIME="1000000"  # Too high
    
    run sanitize_inputs
    echo "$output"  # Output for debugging
    [ "$status" -eq 1 ]
    
    [[ "$output" == *"Numeric value for MEND_MAX_WAIT_TIME out of range"* ]]
}

# Test 23: sanitize_inputs skips empty values
@test "sanitize_inputs skips empty values" {
    export REPOSITORY=""
    export MEND_EMAIL=""
    
    run sanitize_inputs
    [ "$status" -eq 0 ]
    # Should not contain any sanitization messages for empty values
    [[ "$output" != *"Sanitized REPOSITORY:"* ]]
    [[ "$output" != *"Sanitized MEND_EMAIL:"* ]]
}

# Test 24: sanitize_inputs redacts sensitive information in logs
@test "sanitize_inputs redacts sensitive information in logs" {
    export GITHUB_TOKEN="secret-token"
    export AWS_ACCESS_KEY_ID="secret-key"
    export AWS_SECRET_ACCESS_KEY="secret-access-key"
    export CLICKHOUSE_PASSWORD="secret-password"
    
    run sanitize_inputs
    [ "$status" -eq 0 ]
    [[ "$output" == *"Input sanitization completed successfully"* ]]
    
    # Make sure actual values are not in the output
    [[ "$output" != *"secret-token"* ]]
    [[ "$output" != *"secret-key"* ]]
    [[ "$output" != *"secret-access-key"* ]]
    [[ "$output" != *"secret-password"* ]]
}
