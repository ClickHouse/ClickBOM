#!/bin/bash
# GitHub SBOM download and processing

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Download SBOM from GitHub repository
download_sbom() {
    local repo="$1"
    local output_file="$2"
    local max_attempts=3
    local base_delay=30
    
    log_info "Downloading SBOM from $repo"
    
    # GitHub API URL for SBOM
    local api_url="https://api.github.com/repos/$repo/dependency-graph/sbom"

    # Authentication header
    local auth_header="Authorization: Bearer $GITHUB_TOKEN"
    
    for attempt in $(seq 1 $max_attempts); do
        # Download SBOM file with optimizations for large files
        log_info "Starting SBOM download, attempt $attempt/$max_attempts (may take time for large files)..."

        # Calculate delay for this attempt (exponential backoff)
        local delay=$((base_delay * attempt))

        if curl -L \
                --max-time 600 \
                --connect-timeout 60 \
                --retry 2 \
                --retry-delay 10 \
                --retry-max-time 120 \
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
                log_success "SBOM downloaded successfully ($file_size) on attempt $attempt"
            
                # Debug: Show first few lines of downloaded content
                log_debug "First 200 characters of downloaded content:"
                if [[ "${DEBUG:-false}" == "true" ]]; then
                    head -c 200 "$output_file" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g'
                    echo ""
                fi
            
                # Quick validation that it's JSON
                if ! jq . "$output_file" > /dev/null 2>&1; then
                    log_warning "Downloaded file is not valid JSON on attempt $attempt"
                    log_error "Content preview:"
                    head -n 5 "$output_file" || cat "$output_file"

                    # If not last attempt, continue to retry
                    if [[ $attempt -lt $max_attempts ]]; then
                        log_info "Invalid JSON received, waiting ${delay} seconds before retry..."
                        sleep $delay
                        continue
                    else
                        log_error "Downloaded file is not valid JSON after all attempts"
                        exit 1
                    fi
                fi
            
                # Check if it looks like an error response
                if jq -e '.message' "$output_file" > /dev/null 2>&1; then
                    local error_message
                    error_message=$(jq -r '.message' "$output_file")
                    # Check if it's a timeout or generation error that we can retry
                    if [[ "$error_message" =~ "Request timed out" ]] || [[ "$error_message" =~ "Failed to generate SBOM" ]] || [[ "$error_message" =~ "timeout" ]]; then
                        log_warning "GitHub SBOM generation timed out on attempt $attempt: $error_message"
                        
                        if [[ $attempt -lt $max_attempts ]]; then
                            log_info "GitHub's SBOM generation timed out, waiting ${delay} seconds before retry..."
                            sleep $delay
                            continue
                        else
                            log_error "GitHub SBOM generation failed after $max_attempts attempts"
                            log_error "Final error: $error_message"
                            log_error "This repository may be too large or complex for GitHub's SBOM generation"
                            log_error "Possible solutions:"
                            log_error "  - Try again later when GitHub's service load is lower"
                            log_error "  - Consider using alternative SBOM sources (Mend, Wiz)"
                            log_error "  - Break down the repository analysis into smaller components"
                            exit 1
                        fi
                    else
                        # Non-retryable error
                        log_error "GitHub API returned error: $error_message"
                        exit 1
                    fi
                fi

                # Success - SBOM downloaded and validated
                log_success "SBOM download completed successfully"
                return 0
            else
                log_error "Downloaded file is empty or missing on attempt $attempt"
                if [[ $attempt -lt $max_attempts ]]; then
                    log_info "Empty file received, waiting ${delay} seconds before retry..."
                    sleep $delay
                    continue
                else
                    log_error "Downloaded file is empty or missing after all attempts"
                    exit 1
                fi
            fi
        else
            local curl_exit_code=$?
            log_warning "Curl failed on attempt $attempt with exit code: $curl_exit_code"
            
            if [[ $attempt -lt $max_attempts ]]; then
                log_info "Network request failed, waiting ${delay} seconds before retry..."
                sleep $delay
                continue
            else
                log_error "Failed to download SBOM file after $max_attempts attempts"
                log_error "This could be due to:"
                log_error "  - Repository is too large for GitHub's SBOM generation (common cause)"
                log_error "  - GitHub's SBOM service is experiencing high load or issues"
                log_error "  - Network connectivity problems"
                log_error "  - Authentication issues with the provided token"
                log_error "  - Repository doesn't have dependency graph enabled"
                log_error "  - SBOM feature not available for this repository type"
                exit 1
            fi
        fi
    done
}
