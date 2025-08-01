#!/bin/bash
# GitHub SBOM download and processing

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Download SBOM from GitHub repository
download_sbom() {
    local repo="$1"
    local output_file="$2"
    
    log_info "Downloading SBOM from $repo"
    
    # GitHub API URL for SBOM
    local api_url="https://api.github.com/repos/$repo/dependency-graph/sbom"

    # Authentication header
    local auth_header="Authorization: Bearer $GITHUB_TOKEN"
    
    # Download SBOM file with optimizations for large files
    log_info "Starting SBOM download (may take time for large files)..."

    if curl -L \
            --max-time 300 \
            --connect-timeout 30 \
            --retry 3 \
            --retry-delay 5 \
            --retry-max-time 180 \
            --silent \
            --show-error \
            --compressed \
            -H "Accept: application/vnd.github+json" \
            -H "$auth_header" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "$api_url" \
            -o "$output_file"; then
        # Verify the download
        if [[ -f "$output_file" && -s "$output_file" ]]; then
            local file_size
            file_size=$(du -h "$output_file" | cut -f1)
            log_success "SBOM downloaded successfully ($file_size)"
            
            # Debug: Show first few lines of downloaded content
            log_debug "First 200 characters of downloaded content:"
            if [[ "${DEBUG:-false}" == "true" ]]; then
                head -c 200 "$output_file" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g'
                echo ""
            fi
            
            # Quick validation that it's JSON
            if ! jq . "$output_file" > /dev/null 2>&1; then
                log_error "Downloaded file is not valid JSON"
                log_error "Content preview:"
                head -n 5 "$output_file" || cat "$output_file"
                exit 1
            fi
            
            # Check if it looks like an error response
            if jq -e '.message' "$output_file" > /dev/null 2>&1; then
                local error_message
                error_message=$(jq -r '.message' "$output_file")
                log_error "GitHub API returned error: $error_message"
                exit 1
            fi
        else
            log_error "Downloaded file is empty or missing"
            exit 1
        fi
    else
        log_error "Failed to download SBOM file"
        log_error "This could be due to:"
        log_error "  - Network timeout (file too large)"
        log_error "  - Authentication issues"
        log_error "  - Repository doesn't have dependency graph enabled"
        log_error "  - SBOM not available for this repository"
        exit 1
    fi
}
