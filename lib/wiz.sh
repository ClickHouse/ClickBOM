#!/bin/bash
# Wiz API integration for SBOM downloads

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Authenticate with Wiz API and get access token
authenticate_wiz() {
    log_info "Authenticating with Wiz API"
    
    # Get access token
    local auth_response
    if auth_response=$(curl -s \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Accept: application/json" \
        --data grant_type=client_credentials \
        --data client_id="$WIZ_CLIENT_ID" \
        --data client_secret="$WIZ_CLIENT_SECRET" \
        --data audience=wiz-api \
        "$WIZ_AUTH_ENDPOINT"); then
        
        # Extract access token
        local access_token
        if access_token=$(echo "$auth_response" | jq -r '.access_token // empty'); then
            if [[ -n "$access_token" && "$access_token" != "null" ]]; then
                log_success "Wiz authentication successful"
                WIZ_ACCESS_TOKEN="$access_token"
                return 0
            else
                log_error "Failed to extract access token from response"
                log_error "Response: $auth_response"
                exit 1
            fi
        else
            log_error "Failed to parse authentication response"
            log_error "Response: $auth_response"
            exit 1
        fi
    else
        log_error "Failed to authenticate with Wiz API"
        log_error "Check your API endpoint, client ID, and client secret"
        exit 1
    fi
}

# Download SBOM report from Wiz using GraphQL
download_wiz_report() {
    local output_file="$1"
    
    log_info "Downloading Wiz report: $WIZ_REPORT_ID"
    
    # Authenticate first
    authenticate_wiz
    
    # Prepare GraphQL query
    local graphql_query=$(cat <<'EOF'
{
  "query": "query ReportDownloadUrl($reportId: ID!) { report(id: $reportId) { lastRun { url } } }",
  "variables": {
    "reportId": "%s"
  }
}
EOF
)
    
    # Format the query with the actual report ID
    local formatted_query
    formatted_query=$(printf "$graphql_query" "$WIZ_REPORT_ID")
    
    log_debug "GraphQL query: $formatted_query"
    
    # Execute GraphQL query to get download URL
    local graphql_response
    if graphql_response=$(curl -s \
        -X POST \
        -H "Authorization: Bearer $WIZ_ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        --data "$formatted_query" \
        "$WIZ_API_ENDPOINT/api/graphql"); then
        
        log_debug "GraphQL response: $graphql_response"
        
        # Check for GraphQL errors
        if echo "$graphql_response" | jq -e '.errors' > /dev/null 2>&1; then
            local error_message
            error_message=$(echo "$graphql_response" | jq -r '.errors[0].message // "Unknown GraphQL error"')
            log_error "Wiz GraphQL error: $error_message"
            exit 1
        fi
        
        # Extract download URL
        local download_url
        if download_url=$(echo "$graphql_response" | jq -r '.data.report.lastRun.url // empty'); then
            if [[ -n "$download_url" && "$download_url" != "null" ]]; then
                log_info "Got download URL from Wiz"
                log_debug "Download URL: $download_url"
                
                # Download the report from the URL
                download_wiz_report_from_url "$download_url" "$output_file"
                return 0
            else
                log_error "No download URL found in response"
                log_error "This could mean:"
                log_error "  - Report ID does not exist"
                log_error "  - Report has no completed runs"
                log_error "  - Report URL has expired"
                log_error "Response: $graphql_response"
                exit 1
            fi
        else
            log_error "Failed to parse GraphQL response"
            log_error "Response: $graphql_response"
            exit 1
        fi
    else
        log_error "Failed to execute GraphQL query"
        exit 1
    fi
}

# Download the report from the provided URL
download_wiz_report_from_url() {
    local download_url="$1"
    local output_file="$2"
    
    log_info "Downloading Wiz report from URL"
    
    # Create temporary file for the raw download
    local temp_download="$temp_dir/wiz_raw_download"
    
    # Download the report file from the provided URL
    if curl -L \
        --max-time 300 \
        --connect-timeout 30 \
        --retry 3 \
        --retry-delay 5 \
        --silent \
        --show-error \
        -H "Authorization: Bearer $WIZ_ACCESS_TOKEN" \
        -H "Accept: application/json" \
        "$download_url" \
        -o "$temp_download"; then
        
        # Verify the download
        if [[ -f "$temp_download" && -s "$temp_download" ]]; then
            local file_size
            file_size=$(du -h "$temp_download" | cut -f1)
            log_success "Wiz report downloaded successfully ($file_size)"
            
            # Detect file type and handle compression
            local file_type
            file_type=$(file -b "$temp_download" 2>/dev/null || echo "unknown")
            log_info "Downloaded file type: $file_type"
            
            # Handle different file types
            if [[ "$file_type" =~ "gzip compressed" ]] || [[ "$file_type" =~ "gzip" ]]; then
                log_info "File is gzip compressed, decompressing..."
                if gunzip -c "$temp_download" > "$output_file"; then
                    log_success "File decompressed successfully"
                else
                    log_error "Failed to decompress gzip file"
                    exit 1
                fi
            elif [[ "$file_type" =~ "Zip archive" ]] || [[ "$file_type" =~ "zip" ]] || head -c 2 "$temp_download" | xxd | grep -q "504b"; then
                log_info "File is ZIP archive, extracting..."
                
                # Create extraction directory
                local extract_dir="$temp_dir/wiz_extract"
                mkdir -p "$extract_dir"
                
                # Extract the ZIP file
                if unzip -q "$temp_download" -d "$extract_dir"; then
                    log_success "ZIP file extracted successfully"
                    
                    # Debug: Show what was extracted
                    log_debug "Extracted files:"
                    if [[ "${DEBUG:-false}" == "true" ]]; then
                        find "$extract_dir" -type f | while read -r file; do
                            log_debug "  - $(basename "$file") ($(file -b "$file" 2>/dev/null || echo "unknown type"))"
                        done
                    fi
                    
                    # Find JSON files in the extracted content
                    local json_files
                    json_files=$(find "$extract_dir" -name "*.json" -type f)
                    
                    if [[ -n "$json_files" ]]; then
                        local json_count
                        json_count=$(echo "$json_files" | wc -l)
                        log_info "Found $json_count JSON files in ZIP archive"

                        if [[ $json_count -eq 1 ]]; then
                            # Single JSON file - just copy it
                            local json_file
                            json_file=$(echo "$json_files" | head -1)
                            log_info "Single JSON file: $(basename "$json_file")"
                            
                            if cp "$json_file" "$output_file"; then
                                log_success "JSON file extracted and copied successfully"
                            else
                                log_error "Failed to copy extracted JSON file"
                                exit 1
                            fi
                        else
                            # Multiple JSON files - merge them using existing function
                            log_info "Multiple JSON files found, merging CycloneDX SBOMs..."
                            
                            # Validate all are CycloneDX SBOMs
                            local cyclonedx_files=()
                            while IFS= read -r json_file; do
                                if [[ -f "$json_file" ]]; then
                                    # Check if it's valid JSON first
                                    if jq empty "$json_file" >/dev/null 2>&1; then
                                        # Check if it's CycloneDX
                                        local bom_format
                                        bom_format=$(jq -r '.bomFormat // "missing"' "$json_file" 2>/dev/null)
                                        
                                        if [[ "$bom_format" == "CycloneDX" ]] || jq -e '.metadata.component' "$json_file" >/dev/null 2>&1; then
                                            cyclonedx_files+=("$json_file")
                                            log_debug "  ✓ $(basename "$json_file") is valid CycloneDX"
                                        else
                                            log_warning "  ⚠ $(basename "$json_file") is not CycloneDX (format: $bom_format)"
                                        fi
                                    else
                                        log_warning "  ⚠ $(basename "$json_file") is not valid JSON"
                                    fi
                                fi
                            done <<< "$json_files"
                            
                            if [[ ${#cyclonedx_files[@]} -eq 0 ]]; then
                                log_error "No valid CycloneDX SBOMs found in ZIP archive"
                                exit 1
                            elif [[ ${#cyclonedx_files[@]} -eq 1 ]]; then
                                # Only one valid CycloneDX file found
                                log_info "Only one valid CycloneDX SBOM found, copying it"
                                if cp "${cyclonedx_files[0]}" "$output_file"; then
                                    log_success "CycloneDX SBOM copied successfully"
                                else
                                    log_error "Failed to copy CycloneDX SBOM"
                                    exit 1
                                fi
                            else
                                # Multiple valid CycloneDX files - merge them
                                log_info "Merging ${#cyclonedx_files[@]} CycloneDX SBOMs..."
                                merge_local_cyclonedx_sboms "${cyclonedx_files[@]}" "$output_file"
                            fi
                        fi
                    else
                        log_error "No JSON files found in extracted ZIP"
                        log_info "Looking for any files that might be JSON (without .json extension):"
                        
                        # Try to find files that might be JSON by content
                        local potential_json_files=()
                        while IFS= read -r -d '' file; do
                            if [[ -f "$file" && -s "$file" ]]; then
                                # Check if file content looks like JSON
                                if head -c 1 "$file" | grep -q '[{\[]'; then
                                    potential_json_files+=("$file")
                                    log_info "  - $(basename "$file") might be JSON (starts with { or [)"
                                fi
                            fi
                        done < <(find "$extract_dir" -type f -print0)
                        
                        if [[ ${#potential_json_files[@]} -gt 0 ]]; then
                            log_info "Trying first potential JSON file: $(basename "${potential_json_files[0]}")"
                            if cp "${potential_json_files[0]}" "$output_file"; then
                                log_success "Potential JSON file copied successfully"
                            else
                                log_error "Failed to copy potential JSON file"
                                exit 1
                            fi
                        else
                            log_error "No JSON or JSON-like files found in ZIP archive"
                            log_info "All extracted files:"
                            find "$extract_dir" -type f -exec basename {} \; | sort
                            exit 1
                        fi
                    fi
                    
                    # Cleanup extraction directory
                    rm -rf "$extract_dir"
                else
                    log_error "Failed to extract ZIP file"
                    exit 1
                fi
            else
                # Assume it's already a JSON file
                log_info "File appears to be uncompressed, copying as-is..."
                if cp "$temp_download" "$output_file"; then
                    log_success "File copied successfully"
                else
                    log_error "Failed to copy file"
                    exit 1
                fi
            fi
            
            # Cleanup temp download
            rm -f "$temp_download"
            
            # Validate JSON format
            if jq . "$output_file" > /dev/null 2>&1; then
                log_success "Downloaded report is valid JSON"
                
                # Log some basic info about the report
                local report_info
                if report_info=$(jq -r '.bomFormat // .spdxVersion // .reportType // "unknown"' "$output_file" 2>/dev/null); then
                    log_info "Report format detected: $report_info"
                fi
                
                return 0
            else
                log_error "Downloaded file is not valid JSON after processing"
                log_error "Content preview:"
                head -n 5 "$output_file"
                exit 1
            fi
        else
            log_error "Downloaded file is empty or missing"
            exit 1
        fi
    else
        log_error "Failed to download Wiz report from URL"
        exit 1
    fi
}
