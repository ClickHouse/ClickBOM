#!/usr/bin/env bats

# test/simple.bats
# Simple BATS tests for entrypoint.sh

# Setup function runs before each test
setup() {
    # Load the script to test (source it to access functions)
    # We'll source only the functions, not execute main
    export BATS_TEST_DIRNAME="$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)"
    export PROJECT_ROOT="$(dirname "$BATS_TEST_DIRNAME")"
    
    # Create a temporary test script that sources functions without executing main
    export TEST_SCRIPT="$BATS_TEST_TMPDIR/test_entrypoint.sh"
    
    # Extract only the functions from entrypoint.sh (everything before main function call)
    sed '/^# Run main function/,$d' "$PROJECT_ROOT/entrypoint.sh" > "$TEST_SCRIPT"
    
    # Source the functions
    source "$TEST_SCRIPT"
    
    # Set up test environment variables
    export AWS_ACCESS_KEY_ID="test-key"
    export AWS_SECRET_ACCESS_KEY="test-secret"
    export S3_BUCKET="test-bucket"
    export REPOSITORY="test-owner/test-repo"
    export GITHUB_TOKEN="test-token"
}

# Teardown function runs after each test
teardown() {
    # Clean up any test files or variables if needed
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY S3_BUCKET REPOSITORY GITHUB_TOKEN
}

# Test 1: Basic test to verify BATS is working
@test "basic test - addition" {
    result="$((2 + 2))"
    [ "$result" -eq 4 ]
}

# Test 2: Basic logging functions work
@test "logging functions produce colored output" {
    # Test that log_info produces expected output format
    run log_info "test message"
    
    # Check that the command succeeded (exit code 0)
    [ "$status" -eq 0 ]
    
    # Check that output contains the expected format
    [[ "$output" == *"[INFO]"* ]]
    [[ "$output" == *"test message"* ]]
}

# Test 3: log_error produces error message
@test "log_error produces error message" {
    run log_error "error message"
    
    [ "$status" -eq 0 ]
    [[ "$output" == *"[ERROR]"* ]]
    [[ "$output" == *"error message"* ]]
}

# Test 4: Environment validation
@test "validate_env succeeds with all required variables" {
    # All required variables are already set in setup()
    run validate_env
    
    [ "$status" -eq 0 ]
}

# Test 5: validate_env fails when AWS_SECRET_ACCESS_KEY is missing
@test "validate_env fails when AWS_ACCESS_KEY_ID is missing" {
    unset AWS_ACCESS_KEY_ID
    
    run validate_env
    
    # Should exit with code 1
    [ "$status" -eq 1 ]
    [[ "$output" == *"Required environment variable AWS_ACCESS_KEY_ID is not set"* ]]
}

# Test 6: validate_env fails when AWS_SECRET_ACCESS_KEY is missing
@test "validate_env fails when S3_BUCKET is missing" {
    unset S3_BUCKET
    
    run validate_env
    
    [ "$status" -eq 1 ]
    [[ "$output" == *"Required environment variable S3_BUCKET is not set"* ]]
}

# Test 7: CycloneDXSBOM format detection
@test "detect_sbom_format identifies CycloneDX format" {
    # Create a temporary CycloneDX SBOM file
    local test_sbom="$BATS_TEST_TMPDIR/cyclonedx_test.json"
    cat > "$test_sbom" << 'EOF'
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {
        "component": {
            "name": "test"
        }
    }
}
EOF
    run detect_sbom_format "$test_sbom"

    [ "$status" -eq 0 ]
    [ "$output" = "cyclonedx" ]
}

# Test 8: SPDX format detection
@test "detect_sbom_format identifies SPDX format" {
    # Create a temporary SPDX SBOM file
    local test_sbom="$BATS_TEST_TMPDIR/spdx_test.json"
    cat > "$test_sbom" << 'EOF'
{
    "spdxVersion": "SPDX-2.2",
    "SPDXID": "SPDXRef-DOCUMENT"
}
EOF

    run detect_sbom_format "$test_sbom"
    
    [ "$status" -eq 0 ]
    [ "$output" = "spdxjson" ]
}

# Test 9: Mend environment validation
@test "validate_mend_env succeeds with all required Mend variables when SBOM_SOURCE is mend" {
    export SBOM_SOURCE="mend"
    export MEND_EMAIL="test@example.com"
    export MEND_ORG_UUID="test-org-uuid"
    export MEND_USER_KEY="test-user-key"
    export MEND_BASE_URL="https://saas.mend.io"
    export MEND_PROJECT_UUID="test-project-uuid"
    
    run validate_mend_env
    
    [ "$status" -eq 0 ]
    [[ "$output" == *"Mend environment validated"* ]]
}

# Test 10: validate_mend_env fails when MEND_EMAIL is missing and SBOM_SOURCE is mend
@test "validate_mend_env is skipped when SBOM_SOURCE is not mend" {
    export SBOM_SOURCE="github"
    
    run validate_mend_env
    
    [ "$status" -eq 0 ]
    # Should not contain Mend validation messages since source is github
}

# Test 11: validate_mend_env fails when MEND_EMAIL is missing
@test "validate_mend_env fails when MEND_EMAIL is missing" {
    export SBOM_SOURCE="mend"
    export MEND_ORG_UUID="test-org-uuid"
    export MEND_USER_KEY="test-user-key"
    export MEND_BASE_URL="https://saas.mend.io"
    export MEND_PROJECT_UUID="test-project-uuid"
    # MEND_EMAIL is intentionally not set
    
    run validate_mend_env
    
    [ "$status" -eq 1 ]
    [[ "$output" == *"Required Mend environment variable MEND_EMAIL is not set"* ]]
}

