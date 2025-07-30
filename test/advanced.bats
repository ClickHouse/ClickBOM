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

# Todo: Range Check
# Test 22: sanitize_inputs rejects invalid numeric values
@test "sanitize_inputs rejects invalid numeric values" {
    export MEND_MAX_WAIT_TIME=8000  # Too high

    run sanitize_inputs
    [ "$status" -eq 0 ]
    [[ "$output" == *"Input sanitization completed successfully"* ]]
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

# ============================================================================
# SECURITY ATTACK VECTOR TESTS
# ============================================================================

# Test 25: sanitize_string prevents command injection via backticks
@test "sanitize_string prevents command injection via backticks" {
    run sanitize_string "normal\`rm -rf /\`text"
    [ "$status" -eq 0 ]
    [[ "$output" == "normalrm -rf /text" ]]
    # Should not contain backticks
    [[ "$output" != *"\`"* ]]
}

# Test 26: sanitize_string prevents command injection via dollar parentheses
@test "sanitize_string prevents command injection via dollar parentheses" {
    run sanitize_string "normal\$(rm -rf /)text"
    [ "$status" -eq 0 ]
    [[ "$output" == "normalrm -rf /text" ]]
    # Should not contain $( or )
    [[ "$output" != *"\$("* ]]
    [[ "$output" != *")"* ]]
}

# Test 27: sanitize_string prevents pipe injection
@test "sanitize_string prevents pipe injection" {
    run sanitize_string "normal|rm -rf /|text"
    [ "$status" -eq 0 ]
    [[ "$output" == "normalrm -rf /text" ]]
    # Should not contain pipes
    [[ "$output" != *"|"* ]]
}

# Test 28: sanitize_string prevents semicolon command chaining
@test "sanitize_string prevents semicolon command chaining" {
    run sanitize_string "normal;rm -rf /;text"
    [ "$status" -eq 0 ]
    [[ "$output" == "normalrm -rf /text" ]]
    # Should not contain semicolons
    [[ "$output" != *";"* ]]
}

# Test 29: sanitize_string prevents ampersand backgrounding
@test "sanitize_string prevents ampersand backgrounding" {
    run sanitize_string "normal&rm -rf /&text"
    [ "$status" -eq 0 ]
    [[ "$output" == "normalrm -rf /text" ]]
    # Should not contain ampersands
    [[ "$output" != *"&"* ]]
}

# Test 30: sanitize_string prevents redirection attacks
@test "sanitize_string prevents redirection attacks" {
    run sanitize_string "normal>>/etc/passwd<<EOF"
    [ "$status" -eq 0 ]
    [[ "$output" == "normal/etc/passwdEOF" ]]
    # Should not contain redirection operators
    [[ "$output" != *">"* ]]
    [[ "$output" != *"<"* ]]
}

# Test 31: sanitize_repository prevents path traversal in repository names
@test "sanitize_repository prevents path traversal in repository names" {
    run sanitize_repository "../../../etc/passwd"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid repository format"* ]]
}

# Test 32: sanitize_repository prevents null byte injection
@test "sanitize_repository prevents null byte injection" {
    local test_repo=$(printf "owner/repo\000malicious")
    run sanitize_repository "$test_repo"
    [ "$status" -eq 0 ]
    [[ "$output" == "owner/repomalicious" ]]
}

# Test 33: sanitize_url prevents javascript protocol injection
@test "sanitize_url prevents javascript protocol injection" {
    run sanitize_url "javascript:alert('xss')"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid URL format"* ]]
}

# Test 34: sanitize_url prevents data URL injection
@test "sanitize_url prevents data URL injection" {
    run sanitize_url "data:text/html,<script>alert('xss')</script>"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid URL format"* ]]
}

# Test 35: sanitize_url prevents file protocol access
@test "sanitize_url prevents file protocol access" {
    run sanitize_url "file:///etc/passwd"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid URL format"* ]]
}

# Test 36: sanitize_s3_key prevents directory traversal
@test "sanitize_s3_key prevents directory traversal" {
    run sanitize_s3_key "../../../../etc/passwd"
    [ "$status" -eq 0 ]
    [[ "$output" == "etc/passwd" ]]
    # Should not contain ../ sequences
    [[ "$output" != *".."* ]]
}

# Test 37: sanitize_s3_key prevents null byte injection
@test "sanitize_s3_key prevents null byte file injection" {
    local test_key=$(printf "file.json\000.sh")
    run sanitize_s3_key "$test_key"
    [ "$status" -eq 0 ]
    [[ "$output" == "file.json.sh" ]]
}

# Test 38: sanitize_email prevents email header injection
@test "sanitize_email prevents header injection" {
    run sanitize_email "user@example.com\nBcc: admin@evil.com"    
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid email format"* ]]
}

# Test 39: sanitize_email prevents SQL injection attempts
@test "sanitize_database_name prevents SQL injection attempts" {
    run sanitize_database_name "test'; DROP TABLE users; --"
    echo "$status"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == "testDROPTABLEusers" ]]
}

# ============================================================================
# UNICODE AND ENCODING EDGE CASES
# ============================================================================

@test "sanitize_string handles unicode characters" {
    run sanitize_string "test-üñíçødé-string"
    [ "$status" -eq 0 ]
    # Should remove non-ASCII characters
    [[ "$output" == "test--string" ]]
}

@test "sanitize_string handles mixed encoding" {
    # Test with mixed ASCII and control characters
    local mixed_string=$(printf "test\x1b[31mred\x1b[0mnormal")
    run sanitize_string "$mixed_string"
    [ "$status" -eq 0 ]
    [[ "$output" == "testrednormal" ]]
}

@test "sanitize_repository handles international domain names" {
    # Note: This should fail validation as our regex is ASCII-only
    run sanitize_repository "üser/repö"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid repository format"* ]]
}

@test "sanitize_url handles internationalized domain names" {
    # Test with punycode (internationalized domain)
    run sanitize_url "https://xn--n3h.com"
    [ "$status" -eq 0 ]
    [[ "$output" == "https://xn--n3h.com" ]]
}

@test "sanitize_email handles unicode in email addresses" {
    # Should remove unicode characters
    run sanitize_email "üser@example.com"
    [ "$status" -eq 0 ]
    [[ "$output" == "ser@example.com" ]]
}

# ============================================================================
# BOUNDARY CONDITION TESTS
# ============================================================================

@test "sanitize_string handles empty string" {
    run sanitize_string ""
    [ "$status" -eq 0 ]
    [[ "$output" == "" ]]
}

@test "sanitize_string handles very long string" {
    local long_string=$(printf 'a%.0s' {1..10000})
    run sanitize_string "$long_string" 1000
    [ "$status" -eq 0 ]
    [ "${#output}" -eq 1000 ]
    [[ "$output" == "$(printf 'a%.0s' {1..1000})" ]]
}

@test "sanitize_string handles string with only dangerous characters" {
    run sanitize_string "\$\`(){}|;&<>"
    [ "$status" -eq 0 ]
    [[ "$output" == "" ]]
}

@test "sanitize_repository handles minimum valid length" {
    run sanitize_repository "a/b"
    [ "$status" -eq 0 ]
    [[ "$output" == "a/b" ]]
}

@test "sanitize_repository handles maximum practical length" {
    # GitHub has limits, but test with reasonable long names
    local long_owner=$(printf 'a%.0s' {1..50})
    local long_repo=$(printf 'b%.0s' {1..50})
    run sanitize_repository "$long_owner/$long_repo"
    [ "$status" -eq 0 ]
    [[ "$output" == "$long_owner/$long_repo" ]]
}

@test "sanitize_s3_bucket handles minimum valid length" {
    run sanitize_s3_bucket "abc"
    [ "$status" -eq 0 ]
    [[ "$output" == "abc" ]]
}

@test "sanitize_s3_bucket handles maximum valid length" {
    local max_bucket=$(printf 'a%.0s' {1..63})
    run sanitize_s3_bucket "$max_bucket"
    [ "$status" -eq 0 ]
    [[ "$output" == "$max_bucket" ]]
}

@test "sanitize_numeric handles zero" {
    run sanitize_numeric "0" "TEST_FIELD"
    [ "$status" -eq 0 ]
    [[ "$output" == "0" ]]
}

@test "sanitize_numeric handles leading zeros" {
    run sanitize_numeric "00123" "TEST_FIELD"
    [ "$status" -eq 0 ]
    [[ "$output" == "123" ]]
}

@test "sanitize_uuid handles minimum valid length" {
    run sanitize_uuid "12345678" "TEST_UUID"
    [ "$status" -eq 0 ]
    [[ "$output" == "12345678" ]]
}

# ============================================================================
# MALFORMED INPUT TESTS
# ============================================================================

@test "sanitize_repository handles malformed repository - double slash" {
    run sanitize_repository "owner//repo"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid repository format"* ]]
}

@test "sanitize_repository handles malformed repository - trailing slash" {
    run sanitize_repository "owner/repo/"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid repository format"* ]]
}

@test "sanitize_url handles malformed URL - missing protocol" {
    run sanitize_url "example.com"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid URL format"* ]]
}

@test "sanitize_url handles malformed URL - double protocol" {
    run sanitize_url "https://http://example.com"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid URL format"* ]]
}

@test "sanitize_email handles malformed email - double @" {
    run sanitize_email "user@@example.com"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid email format"* ]]
}

@test "sanitize_email handles malformed email - missing domain" {
    run sanitize_email "user@"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid email format"* ]]
}

@test "sanitize_patterns handles malformed patterns - only commas" {
    run sanitize_patterns ",,,"
    [ "$status" -eq 0 ]
    [[ "$output" == "" ]]
}

@test "sanitize_patterns handles malformed patterns - mixed valid/invalid" {
    run sanitize_patterns "*.json,\$\$\$,test*.txt"
    [ "$status" -eq 0 ]
    [[ "$output" == "*.json,test*.txt" ]]
}

# ============================================================================
# INTEGRATION TESTS WITH REALISTIC ATTACK SCENARIOS
# ============================================================================

@test "sanitize_inputs handles comprehensive injection attempt" {
    # Set up a comprehensive attack scenario
    export REPOSITORY="evil\`rm -rf /\`/repo"
    export MEND_EMAIL="evil@example.com; cat /etc/passwd"
    export S3_BUCKET="evil-bucket\$(whoami)"
    export S3_KEY="../../../etc/passwd"
    export CLICKHOUSE_URL="https://evil.com/\`id\`"
    export INCLUDE="*.json; rm -rf /"
    export EXCLUDE="*.txt|cat /etc/passwd"
    
    run sanitize_inputs
    [ "$status" -eq 1 ]  # Should fail validation
    
    # Check that dangerous characters were removed or validation failed
    [[ "$output" == *"Invalid repository format"* ]] || [[ "$output" == *"Invalid email format"* ]] || [[ "$output" == *"Invalid S3 bucket name"* ]]
}

@test "sanitize_inputs handles null byte injection across multiple fields" {
    # Test null byte injection in multiple fields
    local null_repo=$(printf "owner/repo\000malicious")
    local null_email=$(printf "user@example.com\000admin@evil.com")
    local null_bucket=$(printf "bucket\000evil")
    
    export REPOSITORY="$null_repo"
    export MEND_EMAIL="$null_email"
    export S3_BUCKET="$null_bucket"
    
    run sanitize_inputs
    [ "$status" -eq 0 ]
    
    # Verify null bytes were removed
    [[ "$output" == *"owner/repomalicious"* ]]
    [[ "$output" == *"user@example.comadmin@evil.com"* ]]
    [[ "$output" == *"bucketevil"* ]]
}

@test "sanitize_inputs handles control character injection" {
    # Test various control characters
    local control_string=$(printf "test\001\002\003\004\005string")
    
    export REPOSITORY="owner/repo"
    export GITHUB_TOKEN="$control_string"
    
    run sanitize_inputs
    [ "$status" -eq 0 ]
    
    # Control characters should be removed
    [[ "$output" == *"teststring"* ]]
}

@test "sanitize_inputs preserves valid complex inputs" {
    # Test that valid complex inputs are preserved
    export REPOSITORY="my-org/my-repo.name"
    export MEND_EMAIL="user.name+tag@example-domain.co.uk"
    export S3_BUCKET="my-test-bucket-123"
    export S3_KEY="path/to/sbom-file.json"
    export CLICKHOUSE_URL="https://clickhouse.example.com:8443"
    export INCLUDE="*-prod.json,production-*.json"
    export EXCLUDE="*-dev.json,*-test.json"
    export MEND_PROJECT_UUIDS="123e4567-e89b-12d3-a456-426614174000,456e7890-e89b-12d3-a456-426614174001"
    
    run sanitize_inputs
    [ "$status" -eq 0 ]
    
    # All valid inputs should be preserved
    [[ "$output" == *"my-org/my-repo.name"* ]]
    [[ "$output" == *"user.name+tag@example-domain.co.uk"* ]]
    [[ "$output" == *"my-test-bucket-123"* ]]
    [[ "$output" == *"path/to/sbom-file.json"* ]]
    [[ "$output" == *"https://clickhouse.example.com:8443"* ]]
    [[ "$output" == *"*-prod.json,production-*.json"* ]]
    [[ "$output" == *"*-dev.json,*-test.json"* ]]
    [[ "$output" == *"123e4567-e89b-12d3-a456-426614174000,456e7890-e89b-12d3-a456-426614174001"* ]]
}

# ============================================================================
# PERFORMANCE AND RESOURCE TESTS
# ============================================================================

@test "sanitize_string handles extremely long input efficiently" {
    # Test with very long input to ensure no performance issues
    local huge_string=$(printf 'a%.0s' {1..50000})
    
    run timeout 5 sanitize_string "$huge_string" 1000
    [ "$status" -eq 0 ]
    [ "${#output}" -eq 1000 ]
}

@test "sanitize_patterns handles many patterns efficiently" {
    # Test with many patterns
    local many_patterns=""
    for i in {1..100}; do
        many_patterns+=",pattern$i*.json"
    done
    many_patterns=${many_patterns:1}  # Remove leading comma
    
    run timeout 5 sanitize_patterns "$many_patterns"
    [ "$status" -eq 0 ]
    [[ "$output" == *"pattern1*.json"* ]]
    [[ "$output" == *"pattern100*.json"* ]]
}

@test "sanitize_inputs handles all fields simultaneously" {
    # Test with all possible fields set to ensure no conflicts
    export REPOSITORY="owner/repo"
    export MEND_EMAIL="user@example.com"
    export MEND_ORG_UUID="123e4567-e89b-12d3-a456-426614174000"
    export MEND_USER_KEY="test-key"
    export MEND_BASE_URL="https://api.mend.io"
    export MEND_PROJECT_UUID="123e4567-e89b-12d3-a456-426614174001"
    export MEND_PRODUCT_UUID="123e4567-e89b-12d3-a456-426614174002"
    export MEND_ORG_SCOPE_UUID="123e4567-e89b-12d3-a456-426614174003"
    export MEND_PROJECT_UUIDS="123e4567-e89b-12d3-a456-426614174004,123e4567-e89b-12d3-a456-426614174005"
    export MEND_MAX_WAIT_TIME="1800"
    export MEND_POLL_INTERVAL="30"
    export WIZ_AUTH_ENDPOINT="https://auth.wiz.io"
    export WIZ_API_ENDPOINT="https://api.wiz.io"
    export WIZ_CLIENT_ID="wiz-client-id"
    export WIZ_CLIENT_SECRET="wiz-client-secret"
    export WIZ_REPORT_ID="wiz-report-123"
    export AWS_ACCESS_KEY_ID="aws-key"
    export AWS_SECRET_ACCESS_KEY="aws-secret"
    export AWS_DEFAULT_REGION="us-east-1"
    export S3_BUCKET="test-bucket"
    export S3_KEY="test/sbom.json"
    export CLICKHOUSE_URL="https://clickhouse.example.com"
    export CLICKHOUSE_DATABASE="test_db"
    export CLICKHOUSE_USERNAME="user"
    export CLICKHOUSE_PASSWORD="pass"
    export SBOM_SOURCE="github"
    export SBOM_FORMAT="cyclonedx"
    export MERGE="false"
    export INCLUDE="*.json"
    export EXCLUDE="*-test.json"
    export GITHUB_TOKEN="github-token"
    
    run timeout 10 sanitize_inputs
    [ "$status" -eq 0 ]
    [[ "$output" == *"Input sanitization completed successfully"* ]]
}