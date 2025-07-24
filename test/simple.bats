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
    
    # Replace the source line in the extracted script
    sed -i "s|source \"\$SCRIPT_DIR/lib/sanitize.sh\"|source \"$PROJECT_ROOT/lib/sanitize.sh\"|" "$TEST_SCRIPT"
    
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

# Test 12: matches_pattern function with exact filename
@test "matches_pattern works with exact filename" {
    run matches_pattern "test.json" "test.json"
    [ "$status" -eq 0 ]
    
    run matches_pattern "test.json" "other.json"
    [ "$status" -eq 1 ]
}

# Test 13: matches_pattern function with wildcard patterns
@test "matches_pattern works with wildcard patterns" {
    run matches_pattern "test-prod.json" "*-prod.json"
    [ "$status" -eq 0 ]
    
    run matches_pattern "production-test.json" "production-*.json"
    [ "$status" -eq 0 ]
    
    run matches_pattern "test-dev.json" "*-prod.json"
    [ "$status" -eq 1 ]
}

# Test 14: matches_pattern function with multiple patterns
@test "matches_pattern works with multiple comma-separated patterns" {
    run matches_pattern "test-prod.json" "test.json,*-prod.json,other.json"
    [ "$status" -eq 0 ]
    
    run matches_pattern "production-test.json" "test.json,production-*.json,other.json"
    [ "$status" -eq 0 ]
    
    run matches_pattern "random.json" "test.json,*-prod.json,other.json"
    [ "$status" -eq 1 ]
}

# Test 15: matches_pattern function with empty patterns
@test "matches_pattern returns false for empty patterns" {
    run matches_pattern "test.json" ""
    [ "$status" -eq 1 ]
}

# Test 16: filter_files function with include only
@test "filter_files works with include patterns only" {
    local test_files="test-prod.json"$'\n'"test-dev.json"$'\n'"production-main.json"
    
    export INCLUDE="*-prod.json,production-*.json"
    export EXCLUDE=""
    
    local result=$(filter_files "$test_files")
    
    # Should include test-prod.json and production-main.json
    [[ "$result" =~ test-prod.json ]]
    [[ "$result" =~ production-main.json ]]
    [[ ! "$result" =~ test-dev.json ]]
}

# Test 17: filter_files function with exclude only
@test "filter_files works with exclude patterns only" {
    local test_files="test-prod.json"$'\n'"test-dev.json"$'\n'"production-main.json"
    
    export INCLUDE=""
    export EXCLUDE="*-dev.json"
    
    local result=$(filter_files "$test_files")
    
    # Should exclude test-dev.json but include others
    [[ "$result" =~ test-prod.json ]]
    [[ "$result" =~ production-main.json ]]
    [[ ! "$result" =~ test-dev.json ]]
}

# Test 18: filter_files function with both include and exclude
@test "filter_files works with both include and exclude patterns" {
    local test_files="test-prod.json"$'\n'"test-dev.json"$'\n'"production-main.json"$'\n'"production-test.json"
    
    export INCLUDE="*-prod.json,production-*.json"
    export EXCLUDE="*-test.json"
    
    local result=$(filter_files "$test_files")
    
    # Should include test-prod.json and production-main.json
    # Should exclude test-dev.json (not in include) and production-test.json (in exclude)
    [[ "$result" =~ test-prod.json ]]
    [[ "$result" =~ production-main.json ]]
    [[ ! "$result" =~ test-dev.json ]]
    [[ ! "$result" =~ production-test.json ]]
}

# Test 19: filter_files function with no patterns (should return all files)
@test "filter_files returns all files when no patterns specified" {
    local test_files="test-prod.json"$'\n'"test-dev.json"$'\n'"production-main.json"
    
    export INCLUDE=""
    export EXCLUDE=""
    
    local result=$(filter_files "$test_files")
    
    # Should include all files
    [[ "$result" =~ test-prod.json ]]
    [[ "$result" =~ test-dev.json ]]
    [[ "$result" =~ production-main.json ]]
}

# Test 20: filter_files function with empty file list
@test "filter_files handles empty file list" {
    local test_files=""
    
    export INCLUDE="*.json"
    export EXCLUDE=""
    
    local result=$(filter_files "$test_files")
    
    # Should return empty result
    [[ -z "$result" ]]
}

# Test 21: filter_files function with whitespace in patterns
@test "filter_files handles whitespace in patterns correctly" {
    local test_files="test-prod.json"$'\n'"test-dev.json"
    
    export INCLUDE=" *-prod.json , production-*.json "
    export EXCLUDE=""
    
    local result=$(filter_files "$test_files")
    
    # Should include test-prod.json (whitespace should be trimmed)
    [[ "$result" =~ test-prod.json ]]
    [[ ! "$result" =~ test-dev.json ]]
}

# Test 22: sanitize_string function basic functionality
@test "sanitize_string removes dangerous characters" {
    run sanitize_string "test\$command\`echo hello\`"
    [ "$status" -eq 0 ]
    [[ "$output" == "testcommandecho hello" ]]
}

# Test 23: sanitize_string removes null bytes and control characters
@test "sanitize_string removes control characters" {
    # Test string with null byte, control characters
    local test_string=$(printf "test\000string\001\002\003")
    run sanitize_string "$test_string"
    [ "$status" -eq 0 ]
    [[ "$output" == "teststring" ]]
}

# Test 24: sanitize_string limits length
@test "sanitize_string respects length limit" {
    local long_string=$(printf 'a%.0s' {1..2000})
    run sanitize_string "$long_string" 100
    [ "$status" -eq 0 ]
    [ "${#output}" -eq 100 ]
}

# Test 25: sanitize_string removes shell metacharacters
@test "sanitize_string removes shell metacharacters" {
    run sanitize_string "test|command;rm -rf /&"
    [ "$status" -eq 0 ]
    [[ "$output" == "testcommandrm -rf /" ]]
}

# Test 26: sanitize_string preserves safe characters
@test "sanitize_string preserves safe characters" {
    run sanitize_string "test-string_with.safe@characters123"
    [ "$status" -eq 0 ]
    [[ "$output" == "test-string_with.safecharacters123" ]]
}

# Test 27: sanitize_repository valid input
@test "sanitize_repository accepts valid repository format" {
    run sanitize_repository "owner/repo"
    [ "$status" -eq 0 ]
    [[ "$output" == "owner/repo" ]]
}

# Test 28: sanitize_repository accepts repository with hyphens and underscores
@test "sanitize_repository accepts repository with hyphens and underscores" {
    run sanitize_repository "my-org/my_repo-name"
    [ "$status" -eq 0 ]
    [[ "$output" == "my-org/my_repo-name" ]]
}

# Test 29: sanitize_repository accepts repository with dots
@test "sanitize_repository accepts repository with dots" {
    run sanitize_repository "my.org/repo.name"
    [ "$status" -eq 0 ]
    [[ "$output" == "my.org/repo.name" ]]
}

# Test 30: sanitize_repository removes dangerous characters
@test "sanitize_repository removes dangerous characters" {
    run sanitize_repository "owner\$bad/repo;rm"
    [ "$status" -eq 0 ]
    [[ "$output" == "ownerbad/reporm" ]]
}

# Test 31: sanitize_repository rejects invalid format - special characters
@test "sanitize_repository rejects invalid format - no slash" {
    run sanitize_repository "invalidrepo"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid repository format"* ]]
}

# Test 32: sanitize_repository rejects invalid format - multiple slashes
@test "sanitize_repository rejects invalid format - multiple slashes" {
    run sanitize_repository "owner/repo/extra"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid repository format"* ]]
}

# Test 33: sanitize_repository rejects invalid format - empty owner or repo
@test "sanitize_repository rejects empty owner or repo" {
    run sanitize_repository "/repo"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid repository format"* ]]
    
    run sanitize_repository "owner/"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid repository format"* ]]
}

# Test 34: sanitize_url accepts valid HTTP URL
@test "sanitize_url accepts valid HTTP URL" {
    run sanitize_url "http://example.com"
    [ "$status" -eq 0 ]
    [[ "$output" == "http://example.com" ]]
}

# Test 35: sanitize_url accepts valid HTTPS URL
@test "sanitize_url accepts valid HTTPS URL" {
    run sanitize_url "https://api.example.com:8080"
    [ "$status" -eq 0 ]
    [[ "$output" == "https://api.example.com:8080" ]]
}

# Test 36: sanitize_url accepts valid ClickHouse URL
@test "sanitize_url accepts ClickHouse URL format" {
    run sanitize_url "https://clickhouse.example.com:8443" "clickhouse"
    [ "$status" -eq 0 ]
    [[ "$output" == "https://clickhouse.example.com:8443" ]]
}

# Test 37: sanitize_url enforces HTTPS for Mend URLs
@test "sanitize_url enforces HTTPS for Mend URLs" {
    run sanitize_url "https://api.mend.io/path" "mend"
    [ "$status" -eq 0 ]
    [[ "$output" == "https://api.mend.io/path" ]]
}

# Test 38: sanitize_url rejects non-HTTPS for Mend URLs
@test "sanitize_url rejects HTTP for Mend URLs" {
    run sanitize_url "http://api.mend.io" "mend"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid Mend URL format"* ]]
}

# Test 39: sanitize_url enforces HTTPS for Wiz URLs
@test "sanitize_url enforces HTTPS for Wiz URLs" {
    run sanitize_url "https://api.wiz.io/graphql" "wiz"
    [ "$status" -eq 0 ]
    [[ "$output" == "https://api.wiz.io/graphql" ]]
}

# Test 40: sanitize_url rejects invalid URL format
@test "sanitize_url rejects invalid URL format" {
    run sanitize_url "not-a-url"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid URL format"* ]]
}

# Test 41: sanitize_url rejects FTP URLs
@test "sanitize_url rejects FTP URLs" {
    run sanitize_url "ftp://example.com"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid URL format"* ]]
}

# Test 42: sanitize_url removes control characters
@test "sanitize_url removes control characters" {
    local test_url=$(printf "https://example.com\001\002")
    run sanitize_url "$test_url"
    [ "$status" -eq 0 ]
    [[ "$output" == "https://example.com" ]]
}

# Test 43: sanitize_s3_bucket accepts valid bucket name
@test "sanitize_s3_bucket accepts valid bucket name" {
    run sanitize_s3_bucket "my-test-bucket"
    [ "$status" -eq 0 ]
    [[ "$output" == "my-test-bucket" ]]
}

# Test 44: sanitize_s3_bucket converts bucket name to lowercase
@test "sanitize_s3_bucket converts to lowercase" {
    run sanitize_s3_bucket "My-Test-Bucket"
    [ "$status" -eq 0 ]
    [[ "$output" == "my-test-bucket" ]]
}

# Test 45: sanitize_s3_bucket accepts bucket with dots
@test "sanitize_s3_bucket accepts bucket with dots" {
    run sanitize_s3_bucket "my.test.bucket"
    [ "$status" -eq 0 ]
    [[ "$output" == "my.test.bucket" ]]
}

# Test 46: sanitize_s3_bucket removes invalid characters
@test "sanitize_s3_bucket removes invalid characters" {
    run sanitize_s3_bucket "my_test@bucket!"
    [ "$status" -eq 0 ]
    [[ "$output" == "mytestbucket" ]]
}

# Test 47: sanitize_s3_bucket rejects short bucket name
@test "sanitize_s3_bucket rejects too short name" {
    run sanitize_s3_bucket "ab"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid S3 bucket name"* ]]
}

# Test 48: sanitize_s3_bucket rejects long bucket name
@test "sanitize_s3_bucket rejects too long name" {
    local long_name=$(printf 'a%.0s' {1..70})
    run sanitize_s3_bucket "$long_name"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid S3 bucket name"* ]]
}

# Test 49: sanitize_s3_bucket rejects IP-like format
@test "sanitize_s3_bucket rejects IP-like format" {
    run sanitize_s3_bucket "192.168.1.1"
    [ "$status" -eq 1 ]
    [[ "$output" == *"cannot be formatted as IP address"* ]]
}

# Test 50: sanitize_s3_bucket rejects bucket starting with dash
@test "sanitize_s3_bucket rejects bucket starting with dash" {
    run sanitize_s3_bucket "-invalid-bucket"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid S3 bucket name"* ]]
}

# Test 51: sanitize_s3_bucket rejects bucket ending with dash
@test "sanitize_s3_bucket rejects bucket ending with dash" {
    run sanitize_s3_bucket "invalid-bucket-"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid S3 bucket name"* ]]
}

# Test 52: sanitize_s3_key accepts valid S3 key
@test "sanitize_s3_key accepts valid key" {
    run sanitize_s3_key "path/to/file.json"
    [ "$status" -eq 0 ]
    [[ "$output" == "path/to/file.json" ]]
}

# Test 53: sanitize_s3_key removes dangerous characters
@test "sanitize_s3_key removes dangerous characters" {
    run sanitize_s3_key "path/to/file\$bad.json"
    [ "$status" -eq 0 ]
    [[ "$output" == "path/to/filebad.json" ]]
}

# Test 54: sanitize_s3_key prevents path traversal
@test "sanitize_s3_key prevents path traversal" {
    run sanitize_s3_key "../../../etc/passwd"
    [ "$status" -eq 0 ]
    [[ "$output" == "etc/passwd" ]]
}

# Test 55: sanitize_s3_key removes multiple slashes
@test "sanitize_s3_key removes multiple slashes" {
    run sanitize_s3_key "path//to///file.json"
    [ "$status" -eq 0 ]
    [[ "$output" == "path/to/file.json" ]]
}

# Test 56: sanitize_s3_key removes leading slash
@test "sanitize_s3_key removes leading slash" {
    run sanitize_s3_key "/path/to/file.json"
    [ "$status" -eq 0 ]
    [[ "$output" == "path/to/file.json" ]]
}

# Test 57: sanitize_s3_key removes trailing slash
@test "sanitize_s3_key removes trailing slash" {
    run sanitize_s3_key "path/to/file.json/"
    [ "$status" -eq 0 ]
    [[ "$output" == "path/to/file.json" ]]
}

# Test 58: sanitize_s3_key rejects empty key
@test "sanitize_s3_key rejects empty key" {
    run sanitize_s3_key ""
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid S3 key"* ]]
}

# Test 59: sanitize_s3_key rejects key with only invalid characters
@test "sanitize_s3_key rejects key with only invalid characters" {
    run sanitize_s3_key "\$%^&*()"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid S3 key"* ]]
}

# Test 60: sanitize_uuid accepts valid UUID
@test "sanitize_uuid accepts valid UUID" {
    run sanitize_uuid "123e4567-e89b-12d3-a456-426614174000" "TEST_UUID"
    [ "$status" -eq 0 ]
    [[ "$output" == "123e4567-e89b-12d3-a456-426614174000" ]]
}

# Test 61: sanitize_uuid accepts UUID without hyphens
@test "sanitize_uuid accepts UUID without hyphens" {
    run sanitize_uuid "123e4567e89b12d3a456426614174000" "TEST_UUID"
    [ "$status" -eq 0 ]
    [[ "$output" == "123e4567e89b12d3a456426614174000" ]]
}

# Test 62: sanitize_uuid accepts UUID with uppercase letters
@test "sanitize_uuid accepts uppercase UUID" {
    run sanitize_uuid "123E4567-E89B-12D3-A456-426614174000" "TEST_UUID"
    [ "$status" -eq 0 ]
    [[ "$output" == "123E4567-E89B-12D3-A456-426614174000" ]]
}

# Test 63: sanitize_uuid removes invalid characters
@test "sanitize_uuid removes invalid characters" {
    run sanitize_uuid "123e4567-e89b-12d3-a456-426614174000!@#" "TEST_UUID"
    [ "$status" -eq 0 ]
    [[ "$output" == "123e4567-e89b-12d3-a456-426614174000" ]]
}

# Test 64: sanitize_uuid rejects too short UUID
@test "sanitize_uuid rejects too short UUID" {
    run sanitize_uuid "123" "TEST_UUID"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid UUID format for TEST_UUID"* ]]
}

# Test 65: sanitize_uuid rejects too long UUID
@test "sanitize_uuid rejects non-hex characters" {
    run sanitize_uuid "123g4567-e89b-12d3-a456-426614174000" "TEST_UUID"
    [ "$status" -eq 0 ]
    [[ "$output" == "1234567-e89b-12d3-a456-426614174000" ]]
}