#!/bin/bash
# Mend API integration for SBOM downloads

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Authenticate with Mend API and get JWT token
authenticate_mend() {
    log_info "Authenticating with Mend API 3.0"
    
    # Step 1: Login to get refresh token
    log_info "Step 1: Logging in to get refresh token"
    local login_payload=$(cat <<EOF
{
    "email": "$MEND_EMAIL",
    "orgUuid": "$MEND_ORG_UUID",
    "userKey": "$MEND_USER_KEY"
}
EOF
)
    
    local login_response
    if login_response=$(curl -s \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        --data "$login_payload" \
        "$MEND_BASE_URL/api/v3.0/login"); then
        
        log_debug "Login response: $login_response"
        
        # Extract refresh token from login response
        local refresh_token
        if refresh_token=$(echo "$login_response" | jq -r '.response.refreshToken // empty'); then
            if [[ -n "$refresh_token" && "$refresh_token" != "null" ]]; then
                log_success "Login successful, refresh token obtained"
                log_debug "Refresh token length: ${#refresh_token}"
                
                # Debug: Check if login response already contains JWT
                local login_jwt
                if login_jwt=$(echo "$login_response" | jq -r '.response.jwtToken // empty'); then
                    if [[ -n "$login_jwt" && "$login_jwt" != "null" && "$login_jwt" != "empty" ]]; then
                        log_info "JWT token found directly in login response"
                        MEND_JWT_TOKEN="$login_jwt"
                        return 0
                    fi
                fi
                
                # Step 2: Use refresh token to get JWT token
                log_info "Step 2: Getting JWT token using refresh token"
                log_debug "Using refresh token of length: ${#refresh_token}"
                log_debug "Base URL: $MEND_BASE_URL"
                
                # For saas.mend.io, try the correct API endpoint
                local jwt_response

                # Try POST to /api/v3.0/login/accessToken with empty body
                log_debug "Trying POST /api/v3.0/login/accessToken with empty body"
                jwt_response=$(curl -s \
                    -X POST \
                    -H "wss-refresh-token: $refresh_token" \
                    -H "Content-Type: application/json" \
                    -H "Accept: application/json" \
                    "$MEND_BASE_URL/api/v3.0/login/accessToken")
                
                log_debug "Response (POST empty body): $jwt_response"
                
                # Check if this worked
                local jwt_token
                jwt_token=$(echo "$jwt_response" | jq -r '.response.jwtToken // empty' 2>/dev/null)
                if [[ -n "$jwt_token" && "$jwt_token" != "null" && "$jwt_token" != "empty" ]]; then
                    log_success "JWT token obtained via POST with empty body"
                    MEND_JWT_TOKEN="$jwt_token"
                    return 0
                fi
            else
                log_error "Failed to extract refresh token from login response"
                log_error "Login response: $login_response"
                exit 1
            fi
        else
            log_error "Failed to parse login response"
            log_error "Response: $login_response"
            exit 1
        fi
    else
        log_error "Failed to authenticate with Mend"
        log_error "Check your email, org UUID, and user key credentials"
        log_error "Response: $login_response"
        exit 1
    fi
}

# Request SBOM export from Mend API 3.0
request_mend_sbom_export() {
    local output_file="$1"
    
    log_info "Requesting SBOM export from Mend API 3.0"
    
    # Authenticate first to get JWT token
    authenticate_mend
    
    # Build the request payload
    local payload=$(cat <<EOF
{
    "name": "test",
    "reportType": "cycloneDX_1_5",
    "format": "json",
    "includeVulnerabilities": false
EOF
)

    # Add scope based on what's provided
    if [[ -n "${MEND_PROJECT_UUID:-}" ]]; then
        log_info "Using project scope: $MEND_PROJECT_UUID"
        payload+=",\"scopeType\": \"project\",\"scopeUuid\": \"$MEND_PROJECT_UUID\""
        
        # Add specific project UUIDs if provided
        if [[ -n "${MEND_PROJECT_UUIDS:-}" ]]; then
            local project_array=$(echo "$MEND_PROJECT_UUIDS" | jq -R 'split(",") | map(. | tostring)')
            payload+=",\"projectUuids\": $project_array"
        fi
    elif [[ -n "${MEND_PRODUCT_UUID:-}" ]]; then
        log_info "Using product scope: $MEND_PRODUCT_UUID"
        payload+=",\"scopeType\": \"product\",\"scopeUuid\": \"$MEND_PRODUCT_UUID\""
        
        # Add specific project UUIDs if provided for product scope
        if [[ -n "${MEND_PROJECT_UUIDS:-}" ]]; then
            local project_array=$(echo "$MEND_PROJECT_UUIDS" | jq -R 'split(",") | map(. | tostring)')
            payload+=",\"projectUuids\": $project_array"
        fi
    elif [[ -n "${MEND_ORG_SCOPE_UUID:-}" ]]; then
        log_info "Using organization scope: $MEND_ORG_SCOPE_UUID"
        payload+=",\"scopeType\": \"organization\",\"scopeUuid\": \"$MEND_ORG_SCOPE_UUID\""
    fi
    
    payload+="}"
    
    log_debug "Request payload: $payload"
    
    # Make the export request using JWT token
    local export_response
    if export_response=$(curl -s \
        -X POST \
        -H "Authorization: Bearer $MEND_JWT_TOKEN" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        --data "$payload" \
        "$MEND_BASE_URL/api/v3.0/projects/$MEND_PROJECT_UUID/dependencies/reports/SBOM"); then

        log_success "SBOM export request submitted successfully"
        log_debug "Export response: $export_response"
        
        # Extract the report UUID from the response
        local report_uuid
        if report_uuid=$(echo "$export_response" | jq -r '.response.uuid // empty'); then
            if [[ -n "$report_uuid" && "$report_uuid" != "null" ]]; then
                log_info "Report UUID: $report_uuid"
                
                # Wait for the report to be ready and download it
                download_mend_sbom_when_ready "$report_uuid" "$output_file"
            else
                log_error "Failed to extract report UUID from response"
                log_error "Response: $export_response"
                exit 1
            fi
        else
            log_error "Failed to parse export response"
            log_error "Response: $export_response"
            exit 1
        fi
    else
        log_error "Failed to request SBOM export from Mend"
        log_error "Response: $export_response"
        exit 1
    fi
}

# Poll for report completion and download when ready
download_mend_sbom_when_ready() {
    local report_uuid="$1"
    local output_file="$2"
    local max_wait_time=${MEND_MAX_WAIT_TIME:-1800}  # 30 minutes default
    local poll_interval=${MEND_POLL_INTERVAL:-30}    # 30 seconds default
    local elapsed_time=0
    
    log_info "Waiting for SBOM report to be ready (UUID: $report_uuid)"
    log_info "Max wait time: ${max_wait_time}s, Poll interval: ${poll_interval}s"
    
    while [[ $elapsed_time -lt $max_wait_time ]]; do
        log_info "Checking report status... (elapsed: ${elapsed_time}s)"
        
        # Check if JWT token needs refresh (expires every 30 minutes)
        if [[ $elapsed_time -gt 0 && $((elapsed_time % 1500)) -eq 0 ]]; then
            log_info "Refreshing JWT token (25 minutes elapsed)"
            authenticate_mend
        fi
        
        # Check report status
        local status_response
        if status_response=$(curl -s \
            -H "Authorization: Bearer $MEND_JWT_TOKEN" \
            -H "Accept: application/json" \
            "$MEND_BASE_URL/api/v3.0/orgs/$MEND_ORG_UUID/reports/$report_uuid"); then

            local status
            status=$(echo "$status_response" | jq -r '.response.status // "UNKNOWN"')
            
            log_info "Report status: $status"
            
            case "$status" in
                "COMPLETED"|"SUCCESS")
                    log_success "Report is ready for download"
                    
                    # Download the report
                    if download_mend_report "$report_uuid" "$output_file"; then
                        return 0
                    else
                        log_error "Failed to download completed report"
                        exit 1
                    fi
                    ;;
                "FAILED"|"CANCELED")
                    log_error "Report generation failed with status: $status"
                    log_error "Status response: $status_response"
                    exit 1
                    ;;
                "PENDING"|"IN_PROGRESS")
                    log_info "Report still processing, waiting ${poll_interval}s..."
                    sleep "$poll_interval"
                    elapsed_time=$((elapsed_time + poll_interval))
                    ;;
                *)
                    log_warning "Unknown report status: $status"
                    sleep "$poll_interval"
                    elapsed_time=$((elapsed_time + poll_interval))
                    ;;
            esac
        else
            log_warning "Failed to check report status, retrying..."
            sleep "$poll_interval"
            elapsed_time=$((elapsed_time + poll_interval))
        fi
    done
    
    log_error "Timeout waiting for SBOM report to complete after ${max_wait_time}s"
    exit 1
}

# Download the completed report
download_mend_report() {
    local report_uuid="$1"
    local output_file="$2"
    
    log_info "Downloading SBOM report (UUID: $report_uuid)"
    
    # Download the report with retry logic
    local max_attempts=3
    local attempt=1
    local download_file="$temp_dir/mend_download_$report_uuid.zip"
    
    while [[ $attempt -le $max_attempts ]]; do
        log_info "Download attempt $attempt/$max_attempts"
        
        if curl -L \
            --max-time 600 \
            --connect-timeout 30 \
            --retry 3 \
            --retry-delay 5 \
            --silent \
            --show-error \
            --compressed \
            -H "Authorization: Bearer $MEND_JWT_TOKEN" \
            -H "Accept: application/json" \
            "$MEND_BASE_URL/api/v3.0/orgs/$MEND_ORG_UUID/reports/download/$report_uuid" \
            -o "$download_file"; then
            
            # Verify the download
            if [[ -f "$download_file" && -s "$download_file" ]]; then
                local file_size
                file_size=$(du -h "$download_file" | cut -f1)
                log_success "Mend SBOM downloaded successfully ($file_size)"
                
                # Check if it's a ZIP file (most common for Mend reports)
                local file_type
                file_type=$(file -b "$download_file" 2>/dev/null || echo "unknown")
                log_debug "Downloaded file type: $file_type"
                
                if [[ "$file_type" =~ "Zip archive" ]] || [[ "$file_type" =~ "zip" ]] || head -c 2 "$download_file" | xxd | grep -q "504b"; then
                    log_info "Downloaded file is a ZIP archive, extracting..."
                    
                    # Create extraction directory
                    local extract_dir="$temp_dir/mend_extract_$report_uuid"
                    mkdir -p "$extract_dir"
                    
                    # Extract the ZIP file
                    if unzip -q "$download_file" -d "$extract_dir"; then
                        log_success "ZIP file extracted successfully"
                        
                        # Find JSON files in the extracted content
                        local json_files
                        json_files=$(find "$extract_dir" -name "*.json" -type f)
                        
                        if [[ -n "$json_files" ]]; then
                            # Use the first JSON file found (should be the SBOM)
                            local sbom_file
                            sbom_file=$(echo "$json_files" | head -n 1)
                            log_info "Found SBOM file: $(basename "$sbom_file")"
                            
                            # Copy the extracted JSON to our output file
                            if cp "$sbom_file" "$output_file"; then
                                log_success "SBOM extracted and copied successfully"
                                
                                # Validate JSON format
                                if jq . "$output_file" > /dev/null 2>&1; then
                                    log_success "Extracted SBOM is valid JSON"
                                    
                                    # Log some basic info about the SBOM
                                    local sbom_info
                                    if sbom_info=$(jq -r '.bomFormat // .spdxVersion // "unknown"' "$output_file" 2>/dev/null); then
                                        log_info "SBOM format detected: $sbom_info"
                                    fi
                                    
                                    # Cleanup
                                    rm -rf "$extract_dir" "$download_file"
                                    return 0
                                else
                                    log_error "Extracted file is not valid JSON"
                                    log_error "Content preview:"
                                    head -n 5 "$output_file"
                                fi
                            else
                                log_error "Failed to copy extracted SBOM file"
                            fi
                        else
                            log_error "No JSON files found in extracted ZIP"
                            log_info "Extracted files:"
                            find "$extract_dir" -type f | head -10
                        fi
                        
                        # Cleanup extraction directory
                        rm -rf "$extract_dir"
                    else
                        log_error "Failed to extract ZIP file"
                        log_error "ZIP file might be corrupted"
                    fi
                    
                    # Cleanup download file
                    rm -f "$download_file"
                else
                    # Not a ZIP file, try to process as direct JSON
                    log_info "Downloaded file is not a ZIP archive, processing as direct JSON"
                    
                    # Move download to output file
                    if mv "$download_file" "$output_file"; then
                        # Validate JSON format
                        if jq . "$output_file" > /dev/null 2>&1; then
                            log_success "Downloaded SBOM is valid JSON"
                            
                            # Log some basic info about the SBOM
                            local sbom_info
                            if sbom_info=$(jq -r '.bomFormat // .spdxVersion // "unknown"' "$output_file" 2>/dev/null); then
                                log_info "SBOM format detected: $sbom_info"
                            fi
                            
                            return 0
                        else
                            log_error "Downloaded file is not valid JSON"
                            log_error "Content preview:"
                            head -n 5 "$output_file"
                            log_error "File type: $file_type"
                        fi
                    else
                        log_error "Failed to move downloaded file"
                    fi
                fi
            else
                log_error "Downloaded file is empty or missing"
            fi
        else
            log_warning "Download attempt $attempt failed"
        fi
        
        attempt=$((attempt + 1))
        if [[ $attempt -le $max_attempts ]]; then
            log_info "Waiting 10s before retry..."
            sleep 10
        fi
    done
    
    log_error "Failed to download Mend SBOM after $max_attempts attempts"
    exit 1
}