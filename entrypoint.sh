#!/bin/bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Validate required environment variables
validate_env() {
    local required_vars=("AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "S3_BUCKET" "REPOSITORY")
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required environment variable $var is not set"
            exit 1
        fi
    done
}

# Download SBOM from GitHub repository
download_sbom() {
    local repo="$1"
    local output_file="$2"
    
    log_info "Downloading SBOM from $repo"
    
    # GitHub API URL for file content
    local api_url="https://api.github.com/repos/$repo/dependency-graph/sbom"

    # Determine which token to use
    local auth_header=""
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        auth_header="Authorization: Bearer $GITHUB_TOKEN"
    elif [[ -n "${GHAPP_TOKEN:-}" ]]; then
        auth_header="Authorization: Bearer $GHAPP_TOKEN"
    else
        log_error "No valid GitHub token found. Set GITHUB_TOKEN or GHAPP_TOKEN."
        exit 1
    fi
    
    # Download SBOM file
    if curl -L \
            -H "Accept: application/vnd.github+json" \
            -H "$auth_header" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "$api_url" \
            -o "$output_file"; then
        log_success "SBOM downloaded successfully"
    else
        log_error "Failed to download SBOM file"
        exit 1
    fi
}

# Extract SBOM from wrapper if needed
extract_sbom_from_wrapper() {
    local input_file="$1"
    local output_file="$2"
    
    # Check if the file has the .sbom wrapper structure
    if jq -e '.sbom' "$input_file" > /dev/null 2>&1; then
        log_info "Detected SBOM wrapper, extracting nested SBOM"
        if jq '.sbom' "$input_file" > "$output_file"; then
            log_success "SBOM extracted from wrapper"
        else
            log_error "Failed to extract SBOM from wrapper"
            exit 1
        fi
    else
        log_info "No wrapper detected, using SBOM as-is"
        cp "$input_file" "$output_file"
    fi
}

# Detect SBOM format
detect_sbom_format() {
    local sbom_file="$1"
    
    if ! [[ -f "$sbom_file" ]]; then
        log_error "SBOM file not found: $sbom_file"
        exit 1
    fi
    
    # Check if it's already CycloneDX format
    if jq -e '.bomFormat // .metadata.component' "$sbom_file" > /dev/null 2>&1; then
        local format
        format=$(jq -r '.bomFormat // "cyclonedx"' "$sbom_file" 2>/dev/null || echo "unknown")
        
        if [[ "$format" == "CycloneDX" ]] || jq -e '.metadata.component' "$sbom_file" > /dev/null 2>&1; then
            echo "cyclonedx"
            return
        fi
    fi
    
    # Check if it's SPDX format
    if jq -e '.spdxVersion // .SPDXID' "$sbom_file" > /dev/null 2>&1; then
        echo "spdx"
        return
    fi
    
    # Check if it's SWID format (basic check)
    if jq -e '.SoftwareIdentity' "$sbom_file" > /dev/null 2>&1; then
        echo "swid"
        return
    fi
    
    log_warning "Unable to detect SBOM format, assuming SPDX"
    echo "spdx"
}

# Convert SBOM to desired format
convert_sbom() {
    local input_file="$1"
    local output_file="$2"
    local detected_format="$3"
    local desired_format="$4"

    # If no desired format specified, keep original
    if [[ -z "$desired_format" ]]; then
        log_info "No format conversion requested, keeping original format ($detected_format)"
        cp "$input_file" "$output_file"
        return
    fi

    # Normalize format names for comparison
    local detected_lower=$(echo "$detected_format" | tr '[:upper:]' '[:lower:]')
    local desired_lower=$(echo "$desired_format" | tr '[:upper:]' '[:lower:]')

    # If already in desired format, no conversion needed
    if [[ "$detected_lower" == "$desired_lower" ]]; then
        log_info "SBOM is already in the desired format ($desired_format)"
        cp "$input_file" "$output_file"
        return
    fi

    # Perform conversion based on desired format
    case "$desired_lower" in
        "cyclonedx")
            log_info "Converting $detected_format SBOM to CycloneDX format"
            if cyclonedx convert --input-file "$input_file" --output-file "$output_file" --output-format json; then
                log_success "SBOM converted to CycloneDX format"
            else
                log_error "Failed to convert SBOM to CycloneDX format"
                exit 1
            fi
            ;;
        "spdx")
            log_info "Converting $detected_format SBOM to SPDX format"
            if cyclonedx convert --input-file "$input_file" --output-file "$output_file" --output-format spdxjson; then
                log_success "SBOM converted to SPDX format"
            else
                log_error "Failed to convert SBOM to SPDX format"
                exit 1
            fi
            ;;
        *)
            log_error "Unsupported target format: $desired_format"
            log_error "Supported formats: cyclonedx, spdx"
            exit 1
            ;;
    esac
}

# Upload to S3
upload_to_s3() {
    local local_file="$1"
    local s3_bucket="$2"
    local s3_key="$3"
    
    log_info "Uploading CycloneDX SBOM to s3://$s3_bucket/$s3_key"
    
    if aws s3 cp "$local_file" "s3://$s3_bucket/$s3_key" \
        --content-type "application/json" \
        --metadata "format=cyclonedx,source=github-action"; then
        log_success "SBOM uploaded successfully to S3"
    else
        log_error "Failed to upload SBOM to S3"
        exit 1
    fi
}

# Global variable for temp directory (so cleanup can access it)
temp_dir=""

# Cleanup function
cleanup() {
    if [[ -n "$temp_dir" && -d "$temp_dir" ]]; then
        log_info "Cleaning up temporary files"
        rm -rf "$temp_dir"
    fi
}

# Main function
main() {
    log_info "Starting ClickBOM GitHub Action for SBOM processing"
    
    # Validate environment
    validate_env
    
    # Set defaults for optional variables
    local s3_key="${S3_KEY:-sbom.json}"
    local desired_format="${SBOM_FORMAT:-cyclonedx}"
    
    # Set up cleanup trap    
    trap cleanup EXIT

    # Temporary files
    if ! temp_dir=$(mktemp -d); then
        log_error "Failed to create temporary directory"
        exit 1
    fi

    local original_sbom="$temp_dir/original_sbom.json"
    local extracted_sbom="$temp_dir/extracted_sbom.json"
    local processed_sbom="$temp_dir/processed_sbom.json"
    
    # Download SBOM
    download_sbom "$REPOSITORY" "$original_sbom"

    # Extract SBOM from wrapper if needed
    extract_sbom_from_wrapper "$original_sbom" "$extracted_sbom"

    # Detect format
    local detected_format
    detected_format=$(detect_sbom_format "$extracted_sbom")
    log_info "Detected SBOM format: $detected_format"

    # Convert or copy SBOM based on desired format
    convert_sbom "$extracted_sbom" "$processed_sbom" "$detected_format" "$desired_format"

    cat "$extracted_sbom"
    cat "$processed_sbom"
    
    # Validate the converted file
    if ! jq . "$cyclonedx_sbom" > /dev/null 2>&1; then
        log_error "Generated CycloneDX SBOM is not valid JSON"
        exit 1
    fi
    
    # Upload to S3
#    upload_to_s3 "$cyclonedx_sbom" "$S3_BUCKET" "$s3_key"
    
#    log_success "SBOM processing completed successfully!"
#    log_info "CycloneDX SBOM available at: s3://$S3_BUCKET/$s3_key"
}

# Run main function
main "$@"