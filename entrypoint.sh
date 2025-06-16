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
    local sbom_path="$2"
    local ref="$3"
    local output_file="$4"
    
    log_info "Downloading SBOM from $repo at $ref:$sbom_path"
    
    # GitHub API URL for file content
    local api_url="https://api.github.com/repos/$repo/contents/$sbom_path"
    
    # Add ref parameter if not default
    if [[ "$ref" != "main" ]]; then
        api_url="$api_url?ref=$ref"
    fi
    
    # Download file metadata to get download URL
    local response
    response=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
                   -H "Accept: application/vnd.github.v3+json" \
                   "$api_url")
    
    # Check if API call was successful
    if ! echo "$response" | jq -e '.download_url' > /dev/null 2>&1; then
        log_error "Failed to get SBOM file information from GitHub API"
        log_error "Response: $response"
        exit 1
    fi
    
    # Extract download URL
    local download_url
    download_url=$(echo "$response" | jq -r '.download_url')
    
    # Download the actual file
    if curl -s -H "Authorization: token $GITHUB_TOKEN" \
            -L "$download_url" \
            -o "$output_file"; then
        log_success "SBOM downloaded successfully"
    else
        log_error "Failed to download SBOM file"
        exit 1
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

# Convert SBOM to CycloneDX format
convert_to_cyclonedx() {
    local input_file="$1"
    local output_file="$2"
    local format="$3"
    
    case "$format" in
        "cyclonedx")
            log_info "SBOM is already in CycloneDX format"
            cp "$input_file" "$output_file"
            ;;
        "spdx")
            log_info "Converting SPDX SBOM to CycloneDX format"
            if cyclonedx-py convert --input-file "$input_file" --output-file "$output_file" --output-format json; then
                log_success "SBOM converted to CycloneDX format"
            else
                log_error "Failed to convert SBOM to CycloneDX format"
                exit 1
            fi
            ;;
        *)
            log_warning "Unsupported format '$format', attempting conversion anyway"
            if cyclonedx-py convert --input-file "$input_file" --output-file "$output_file" --output-format json; then
                log_success "SBOM converted to CycloneDX format"
            else
                log_error "Failed to convert SBOM to CycloneDX format"
                exit 1
            fi
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

# Main function
main() {
    log_info "Starting ClickBOM GitHub Action for SBOM processing"
    
    # Validate environment
    validate_env
    
    # Set defaults for optional variables
    local sbom_path="${SBOM_PATH:-sbom.json}"
    local ref="${REF:-main}"
    local s3_key="${S3_KEY:-sbom.json}"
    
    # Temporary files
    local temp_dir=""
    if ! temp_dir=$(mktemp -d); then
        log_error "Failed to create temporary directory"
        exit 1
    fi
    local original_sbom="$temp_dir/original_sbom.json"
    local cyclonedx_sbom="$temp_dir/cyclonedx_sbom.json"
    echo $temp_dir
    
    # Cleanup function
    cleanup() {
        log_info "Cleaning up temporary files"
        rm -rf "$temp_dir"
    }
    trap cleanup EXIT
    
    # Download SBOM
#    download_sbom "$REPOSITORY" "$sbom_path" "$ref" "$original_sbom"
    
    # Detect format
#    local format
#    format=$(detect_sbom_format "$original_sbom")
#    log_info "Detected SBOM format: $format"
    
    # Convert to CycloneDX
#    convert_to_cyclonedx "$original_sbom" "$cyclonedx_sbom" "$format"
    
    # Validate the converted file
#    if ! jq . "$cyclonedx_sbom" > /dev/null 2>&1; then
#        log_error "Generated CycloneDX SBOM is not valid JSON"
#        exit 1
#    fi
    
    # Upload to S3
#    upload_to_s3 "$cyclonedx_sbom" "$S3_BUCKET" "$s3_key"
    
#    log_success "SBOM processing completed successfully!"
#    log_info "CycloneDX SBOM available at: s3://$S3_BUCKET/$s3_key"
}

# Run main function
main "$@"