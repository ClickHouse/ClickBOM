#!/bin/bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
ORANGE='\033[0;33m'
NC='\033[0m' # No Color

# Logging functions
log_debug() {
    echo -e "${ORANGE}[DEBUG]${NC} $1"
}

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
    local required_vars=("AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "S3_BUCKET")

    # Add REPOSITORY requirement only if not in merge mode
    if [[ "${MERGE:-false}" != "true" && "${SBOM_SOURCE:-}" != "mend" && "${SBOM_SOURCE:-}" != "wiz" ]]; then
        required_vars+=("REPOSITORY")
    fi

    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required environment variable $var is not set"
            exit 1
        fi
    done

    # Validate ClickHouse configuration if any ClickHouse parameter is provided
    if [[ -n "${CLICKHOUSE_URL:-}" ]]; then
        local clickhouse_vars=("CLICKHOUSE_URL" "CLICKHOUSE_DATABASE" "CLICKHOUSE_USERNAME")
        for var in "${clickhouse_vars[@]}"; do
            if [[ -z "${!var:-}" ]]; then
                log_error "If using ClickHouse, $var must be provided"
                exit 1
            fi
        done
        log_info "ClickHouse configuration validated"
    fi
}

# Validate Mend environment variables
validate_mend_env() {
    if [[ "${SBOM_SOURCE:-}" == "mend" ]]; then
        local required_mend_vars=("MEND_EMAIL" "MEND_ORG_UUID" "MEND_USER_KEY" "MEND_BASE_URL")
        
        for var in "${required_mend_vars[@]}"; do
            if [[ -z "${!var:-}" ]]; then
                log_error "Required Mend environment variable $var is not set"
                exit 1
            fi
        done
        
        # Validate at least one scope is provided
        if [[ -z "${MEND_PROJECT_UUID:-}" && -z "${MEND_PRODUCT_UUID:-}" && -z "${MEND_ORG_UUID:-}" ]]; then
            log_error "At least one Mend scope must be provided: MEND_PROJECT_UUID, MEND_PRODUCT_UUID, or MEND_ORG_UUID"
            exit 1
        fi
        
        log_info "Mend environment validated"
    fi
}

# Validate Wiz environment variables
validate_wiz_env() {
    if [[ "${SBOM_SOURCE:-}" == "wiz" ]]; then
        local required_wiz_vars=("WIZ_API_ENDPOINT" "WIZ_CLIENT_ID" "WIZ_CLIENT_SECRET" "WIZ_REPORT_ID")
        
        for var in "${required_wiz_vars[@]}"; do
            if [[ -z "${!var:-}" ]]; then
                log_error "Required Wiz environment variable $var is not set"
                exit 1
            fi
        done
        
        log_info "Wiz environment validated"
    fi
}

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
            log_info "First 200 characters of downloaded content:"
            head -c 200 "$output_file" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g'
            echo ""
            
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

# Authenticate with Wiz API and get access token
authenticate_wiz() {
    log_info "Authenticating with Wiz API"
    
    # Prepare authentication payload
    local auth_payload=$(cat <<EOF
{
    "audience": "wiz-api",
    "grant_type": "client_credentials",
    "client_id": "$WIZ_CLIENT_ID",
    "client_secret": "$WIZ_CLIENT_SECRET"
}
EOF
)
    
    # Get access token
    local auth_response
    if auth_response=$(curl -s \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Accept: application/json" \
        --data "$auth_payload" \
        "$WIZ_AUTH_ENDPOINT"); then
        
        log_debug "Auth response: $auth_response"
        
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
    
    # Download the report file from the provided URL
    if curl -L \
        --max-time 300 \
        --connect-timeout 30 \
        --retry 3 \
        --retry-delay 5 \
        --silent \
        --show-error \
        --compressed \
        -H "Authorization: Bearer $WIZ_ACCESS_TOKEN" \
        -H "Accept: application/json" \
        "$download_url" \
        -o "$output_file"; then
        
        # Verify the download
        if [[ -f "$output_file" && -s "$output_file" ]]; then
            local file_size
            file_size=$(du -h "$output_file" | cut -f1)
            log_success "Wiz report downloaded successfully ($file_size)"
            
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
                log_error "Downloaded file is not valid JSON"
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

# Fix SPDX compatibility issues for CycloneDX conversion
fix_spdx_compatibility() {
    local input_file="$1"
    local output_file="$2"
    
    log_info "Fixing SPDX compatibility issues for CycloneDX conversion"
    
    # Fix referenceCategory values that CycloneDX doesn't recognize
    # Based on SPDX 2.2 spec, valid values are: SECURITY, PACKAGE_MANAGER, PERSISTENT_ID, OTHER
    if jq '
        walk(
            if type == "object" and has("referenceCategory") then
                .referenceCategory = (
                    if .referenceCategory == "PACKAGE-MANAGER" then "PACKAGE_MANAGER"
                    elif .referenceCategory == "SECURITY" then "SECURITY"
                    elif .referenceCategory == "PERSISTENT_ID" then "PERSISTENT_ID"
                    elif .referenceCategory == "OTHER" then "OTHER"
                    else "OTHER"
                    end
                )
            else .
            end
        )
    ' "$input_file" > "$output_file"; then
        log_success "SPDX compatibility fixes applied"
    else
        log_error "Failed to apply SPDX compatibility fixes"
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
        echo "spdxjson"
        return
    fi
    
    # Check if it's SWID format (basic check)
    if jq -e '.SoftwareIdentity' "$sbom_file" > /dev/null 2>&1; then
        echo "swid"
        return
    fi
    
    log_warning "Unable to detect SBOM format, assuming SPDX"
    echo "spdxjson"
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

    # Map detected format to CLI input format
    local cli_input_format="$detected_format"
    case "$detected_lower" in
        "spdxjson") cli_input_format="spdxjson" ;;
        "cyclonedx") cli_input_format="json" ;;
        *) cli_input_format="autodetect" ;;
    esac

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
            if cyclonedx convert --input-file "$input_file" --input-format "$cli_input_format" --output-version v1_6 --output-file "$output_file" --output-format json; then
                log_success "SBOM converted to CycloneDX format"
            else
                log_error "Failed to convert SBOM to CycloneDX format"
                exit 1
            fi
            ;;
        "spdxjson")
            log_info "Converting $detected_format SBOM to SPDX format"
            if cyclonedx convert --input-file "$input_file" --input-format "$cli_input_format" --output-file "$output_file" --output-format spdxjson; then
                log_success "SBOM converted to SPDX format"
            else
                log_error "Failed to convert SBOM to SPDX format"
                exit 1
            fi
            ;;
        *)
            log_error "Unsupported target format: $desired_format"
            log_error "Supported formats: cyclonedx, spdxjson"
            exit 1
            ;;
    esac
}

# Upload to S3
upload_to_s3() {
    local local_file="$1"
    local s3_bucket="$2"
    local s3_key="$3"
    local desired_format="${SBOM_FORMAT:-cyclonedx}"
    
    log_info "Uploading $desired_format SBOM to s3://$s3_bucket/$s3_key"
    
    if aws s3 cp "$local_file" "s3://$s3_bucket/$s3_key" \
        --content-type "application/json" \
        --metadata "format=$desired_format,source=github-action"; then
        log_success "SBOM uploaded successfully to S3"
    else
        log_error "Failed to upload SBOM to S3"
        exit 1
    fi
}

# Download all CycloneDX SBOMs from S3 bucket and merge them
merge_cyclonedx_sboms() {
    local output_file="$1"
    
    log_info "Merging all CycloneDX SBOMs from S3 bucket: $S3_BUCKET"
    
    # Create temporary directory for downloaded SBOMs
    local download_dir="$temp_dir/sboms"
    mkdir -p "$download_dir"
    
    # List all JSON files in the S3 bucket (excluding vulns/ directory)
    log_info "Listing JSON files in S3 bucket (excluding vulns/ directory)..."
    local s3_files
    
    # Debug: Show raw S3 ls output
    log_info "Raw S3 listing for bucket: $S3_BUCKET"
    if ! aws s3 ls "s3://$S3_BUCKET" --recursive; then
        log_error "Failed to list files in S3 bucket: $S3_BUCKET"
        log_error "Check bucket name and AWS permissions"
        exit 1
    fi

    # Extract JSON files (excluding vulns/ directory and target S3_KEY file)
    log_info "Extracting JSON file paths..."
    
    # Debug: Show the filtering process step by step
    local all_files
    all_files=$(aws s3 ls "s3://$S3_BUCKET" --recursive | awk '{print $4}' || true)
    log_info "All files found: $(echo "$all_files" | wc -l) files"
    
    local json_files
    json_files=$(echo "$all_files" | grep '\.json$' || true)
    log_info "JSON files found: $(echo "$json_files" | wc -l) files"
    
    s3_files=$(echo "$json_files" | grep -v 'vulns/' || true)
    log_info "JSON files after excluding vulns/: $(echo "$s3_files" | wc -l) files"
    
    # Also exclude the target S3_KEY file to avoid processing the merged output
    local s3_key_basename=$(basename "${S3_KEY:-sbom.json}")
    s3_files=$(echo "$s3_files" | grep -v "^${s3_key_basename}$" || true)
    log_info "JSON files after excluding target file ($s3_key_basename): $(echo "$s3_files" | wc -l) files"
    
    # Debug: Show what files we're going to process
    log_info "Files to process:"
    echo "$s3_files" | while IFS= read -r file; do
        [[ -n "$file" ]] && log_info "  - $file"
    done

    if [[ -z "$s3_files" ]] || [[ "$(echo "$s3_files" | wc -l)" -eq 0 ]]; then
        log_error "No JSON files found in S3 bucket (excluding vulns/ directory and target file)"
        log_error "Available files were:"
        echo "$all_files" | head -10
        exit 1
    fi

    # Download and validate CycloneDX SBOMs
    local cyclonedx_files=()
    local file_count=0
    local total_files=0
    
    log_info "Starting download loop..."
    
    # Use a different approach to avoid issues with the while loop
    local files_array=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && files_array+=("$line")
    done <<< "$s3_files"
    
    log_info "Processing ${#files_array[@]} files..."
    
    for s3_key_to_merge in "${files_array[@]}"; do
        log_debug "Processing file: '$s3_key_to_merge'"

        # Skip empty entries
        if [[ -z "$s3_key_to_merge" ]]; then
            log_debug "Skipping empty s3_key_to_merge"
            continue
        fi
        
        # Safely increment counter
        total_files=$((total_files + 1))
        
        local filename
        filename=$(basename "$s3_key_to_merge" 2>/dev/null) || {
            log_warning "Failed to get basename for: $s3_key_to_merge"
            continue
        }
        
        local local_file="$download_dir/${filename}"

        log_info "Downloading ($total_files/${#files_array[@]}): s3://$S3_BUCKET/$s3_key_to_merge"

        # Try to download the file
        if aws s3 cp "s3://$S3_BUCKET/$s3_key_to_merge" "$local_file"; then
            log_success "Downloaded: $filename"
            
            # Check if it's a valid CycloneDX SBOM
            log_info "Validating CycloneDX format for: $filename"

            # First check if it's valid JSON
            if jq empty "$local_file" >/dev/null 2>&1; then
                log_info "JSON validation passed for: $filename"
            else
                log_warning "Skipping $filename - not valid JSON"
                continue
            fi

            # Check if it has bomFormat field or CycloneDX structure
            local bom_format
            bom_format=$(jq -r '.bomFormat // "missing"' "$local_file" 2>/dev/null)
            
            # Handle jq failure
            if [[ $? -ne 0 ]]; then
                log_warning "Failed to read bomFormat from $filename"
                bom_format="missing"
            fi
            
            log_info "File $filename has bomFormat: $bom_format"

            # Check if it's CycloneDX (also check for metadata.component as backup)
            local is_cyclonedx=false
            
            if [[ "$bom_format" == "CycloneDX" ]]; then
                is_cyclonedx=true
            elif jq -e '.metadata.component' "$local_file" >/dev/null 2>&1; then
                is_cyclonedx=true
                log_info "Detected CycloneDX via metadata.component field"
            fi
            
            if [[ "$is_cyclonedx" == "true" ]]; then
                cyclonedx_files+=("$local_file")
                file_count=$((file_count + 1))
                log_success "Valid CycloneDX SBOM: $filename"
            else
                log_warning "Skipping $filename - bomFormat is '$bom_format', not 'CycloneDX'"
                
                # Debug: Show structure of the file to understand why it's not recognized
                log_debug "File structure preview for $filename:"
                if jq -r 'keys[]' "$local_file" 2>/dev/null | head -5; then
                    echo "Keys shown above"
                else
                    echo "Unable to read keys from file"
                fi
            fi
        else
            log_error "Failed to download: s3://$S3_BUCKET/$s3_key_to_merge"
            log_error "AWS CLI exit code: $?"
            continue
        fi
    done

    log_info "Downloaded $total_files files, found $file_count valid CycloneDX SBOMs"

    if [[ $file_count -eq 0 ]]; then
        log_error "No valid CycloneDX SBOMs found in S3 bucket"
        log_error "Check that your S3 bucket contains CycloneDX format SBOMs"
        
        # Show what files were actually downloaded for debugging
        log_info "Files that were downloaded but rejected:"
        for file in "$download_dir"/*; do
            if [[ -f "$file" ]]; then
                local fname=$(basename "$file")
                local format_info
                format_info=$(jq -r '.bomFormat // .spdxVersion // "unknown_format"' "$file" 2>/dev/null) || format_info="invalid_json"
                log_info "- $fname: $format_info"
            fi
        done
        exit 1
    fi
    
    log_info "Found $file_count CycloneDX SBOMs to merge"
    
    # Create the merged SBOM structure
    log_info "Creating merged CycloneDX SBOM..."
    
    # Start with a proper CycloneDX template
    local merged_metadata
    merged_metadata=$(cat <<'EOF'
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "",
    "version": 1,
    "metadata": {
        "timestamp": "",
        "tools": [{
            "vendor": "ClickBOM",
            "name": "cyclonedx-merge", 
            "version": "1.0.0"
        }],
        "component": {
            "type": "application",
            "name": "merged-sbom",
            "version": "1.0.0"
        }
    },
    "components": []
}
EOF
)
    
    # Generate a UUID-like serial number and timestamp
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local serial_number
    if command -v uuidgen >/dev/null 2>&1; then
        serial_number="urn:uuid:$(uuidgen)"
    else
        serial_number="urn:uuid:$(openssl rand -hex 16 | sed 's/\(.{8}\)\(.{4}\)\(.{4}\)\(.{4}\)\(.{12}\)/\1-\2-\3-\4-\5/')"
    fi
    
    # Update metadata with actual values
    merged_metadata=$(echo "$merged_metadata" | jq --arg ts "$timestamp" --arg sn "$serial_number" '
        .metadata.timestamp = $ts |
        .serialNumber = $sn
    ')
    
    # Collect all components from all SBOMs
    log_info "Collecting components from all SBOMs..."
    local all_components="$temp_dir/all_components.json"
    
    # Initialize empty array
    echo "[]" > "$all_components"
    
    # Collect all components
    for sbom_file in "${cyclonedx_files[@]}"; do
        local component_count
        component_count=$(jq '.components | length' "$sbom_file" 2>/dev/null) || component_count=0
        log_info "Processing $(basename "$sbom_file"): $component_count components"
        
        # Extract components and append to collection
        if [[ "$component_count" -gt 0 ]]; then
            local temp_components="$temp_dir/temp_components_$(basename "$sbom_file").json"
            if jq '.components[]' "$sbom_file" > "$temp_components" 2>/dev/null; then
                # Merge with existing components
                if jq -s 'flatten' "$all_components" "$temp_components" > "$temp_dir/merged_temp.json"; then
                    mv "$temp_dir/merged_temp.json" "$all_components"
                else
                    log_warning "Failed to merge components from $(basename "$sbom_file")"
                fi
            else
                log_warning "Failed to extract components from $(basename "$sbom_file")"
            fi
        fi
    done
    
    # Remove duplicates based on name+version+purl combination (more reliable deduplication)
    log_info "Removing duplicate components..."
    local unique_components="$temp_dir/unique_components.json"
    if jq 'unique_by((.name // "unknown") + "@" + (.version // "unknown") + "#" + (.purl // ""))' "$all_components" > "$unique_components"; then
        log_success "Deduplication completed"
    else
        log_error "Failed to deduplicate components"
        exit 1
    fi
    
    # Create final merged SBOM
    log_info "Assembling final merged SBOM..."
    if echo "$merged_metadata" | jq --slurpfile comps "$unique_components" '. + {components: $comps[0]}' > "$output_file"; then
        log_success "Final SBOM assembled"
    else
        log_error "Failed to assemble final SBOM"
        exit 1
    fi
    
    # Validate the merged SBOM
    if ! jq . "$output_file" > /dev/null 2>&1; then
        log_error "Generated merged SBOM is not valid JSON"
        exit 1
    fi
    
    # Final validation that it's proper CycloneDX
    if ! jq -e '.bomFormat == "CycloneDX"' "$output_file" > /dev/null 2>&1; then
        log_error "Generated merged SBOM does not have proper CycloneDX format"
        exit 1
    fi
    
    local component_count
    component_count=$(jq '.components | length' "$output_file")
    
    log_success "Successfully merged $file_count SBOMs into one with $component_count unique components"
    
    # Show a summary of what was merged
    log_info "Merge summary:"
    for sbom_file in "${cyclonedx_files[@]}"; do
        local fname=$(basename "$sbom_file" .json)
        local comp_count
        comp_count=$(jq '.components | length' "$sbom_file" 2>/dev/null) || comp_count=0
        log_info "  - $fname: $comp_count components"
    done
}

# Create ClickHouse table if it doesn't exist, or truncate if it does
setup_clickhouse_table() {
    local table_name="$1"
    
    log_info "Setting up ClickHouse table: $table_name"
    
    # Build ClickHouse URL
    local clickhouse_url="${CLICKHOUSE_URL}"
    local auth_params=""
    
    # Use basic auth if username and password are provided
    if [[ -n "${CLICKHOUSE_USERNAME:-}" ]] && [[ -n "${CLICKHOUSE_PASSWORD:-}" ]]; then
        auth_params="-u ${CLICKHOUSE_USERNAME}:${CLICKHOUSE_PASSWORD}"
        log_info "Using basic auth with username: ${CLICKHOUSE_USERNAME}"
    elif [[ -n "${CLICKHOUSE_USERNAME:-}" ]]; then
        auth_params="-u ${CLICKHOUSE_USERNAME}:"
        log_info "Using basic auth with username only: ${CLICKHOUSE_USERNAME}"
    else
        log_info "Using no authentication"
    fi
    
    # Test connection first
    log_info "Testing ClickHouse connection..."
    if ! curl -s ${auth_params} --data "SELECT 1" "${clickhouse_url}" > /dev/null; then
        log_error "ClickHouse connection test failed"
        log_error "Please verify your ClickHouse credentials and URL"
        return 1
    fi
    log_success "ClickHouse connection successful"

    # Check if table exists
    local table_exists
    if table_exists=$(curl -s ${auth_params} --data "SELECT COUNT(*) FROM system.tables WHERE database='${CLICKHOUSE_DATABASE}' AND name='${table_name}'" "${clickhouse_url}"); then
        if [[ "$table_exists" == "1" ]]; then
            log_info "Table $table_name exists, truncating..."
            if curl -s ${auth_params} --data "TRUNCATE TABLE ${CLICKHOUSE_DATABASE}.${table_name}" "${clickhouse_url}"; then
                log_success "Table $table_name truncated"
            else
                log_error "Failed to truncate table $table_name"
                return 1
            fi
        else
            log_info "Creating new table: $table_name"
            local create_table_sql="
            CREATE TABLE ${CLICKHOUSE_DATABASE}.${table_name} (
                name String,
                version String,
                license String,
                inserted_at DateTime DEFAULT now()
            ) ENGINE = MergeTree()
            ORDER BY (name, version, license);
            "
            
            if curl -s ${auth_params} --data "$create_table_sql" "${clickhouse_url}"; then
                log_success "Table $table_name created successfully"
            else
                log_error "Failed to create table $table_name"
                return 1
            fi
        fi
    else
        log_error "Failed to check if table exists"
        return 1
    fi
    return 0
}

map_unknown_licenses() {
    local input_file="$1"
    local output_file="$2"
    
    log_info "Mapping unknown licenses using JSON mappings"
    
    # Convert JSON to TSV temporarily
    local mappings_tsv="$temp_dir/mappings.tsv"
    jq -r 'to_entries[] | [.key, .value] | @tsv' /license-mappings.json > "$mappings_tsv"
    
    # Use awk to apply mappings
    awk -F'\t' '
    BEGIN { OFS="\t" }
    NR==FNR { licenses[$1] = $2; next }
    {
        name = $1; version = $2; license = $3
        if (license == "unknown" || license == "" || license == "null") {
            if (name in licenses) license = licenses[name]
        }
        print name, version, license
    }
    ' "$mappings_tsv" "$input_file" > "$output_file"
    
    log_success "License mapping completed"
}

insert_sbom_data() {
    local sbom_file="$1"
    local table_name="$2"
    local sbom_format="$3"
    
    log_info "Extracting components from $sbom_format SBOM for ClickHouse"
    
    # Build ClickHouse URL
    local clickhouse_url="${CLICKHOUSE_URL}"
    local auth_params=""
    
    # Use basic auth if username and password are provided
    if [[ -n "${CLICKHOUSE_USERNAME:-}" ]] && [[ -n "${CLICKHOUSE_PASSWORD:-}" ]]; then
        auth_params="-u ${CLICKHOUSE_USERNAME}:${CLICKHOUSE_PASSWORD}"
        log_info "Using basic auth with username: ${CLICKHOUSE_USERNAME}"
    elif [[ -n "${CLICKHOUSE_USERNAME:-}" ]]; then
        auth_params="-u ${CLICKHOUSE_USERNAME}:"
        log_info "Using basic auth with username only: ${CLICKHOUSE_USERNAME}"
    fi
    
    # Create temporary file for data
    local data_file="$temp_dir/clickhouse_data.tsv"
    local mapped_data_file="$temp_dir/clickhouse_data_mapped.tsv"
    
    # Extract data based on SBOM format
    case "$sbom_format" in
        "cyclonedx")
            log_info "Sample CycloneDX component with license:"
            jq -r '.components[0] | {name: .name, version: .version, licenses: .licenses}' "$sbom_file" 2>/dev/null || echo "No components found"
            # Extract from CycloneDX format
            jq -r '
                .components[]? // empty |
                [
                    .name // "unknown",
                    .version // "unknown", 
                    (
                        # Try to extract license from multiple sources
                        (
                            # First: Try standard CycloneDX licenses array with content
                            if (.licenses | length) > 0 and (.licenses[0] | keys | length) > 0 then
                                .licenses[0] | (.license.id // .license.name // .id // .name // .expression)
                            else
                                null
                            end
                        ) //
                        (
                            # Second: Try SPDX properties for license-concluded
                            if (.properties | length) > 0 then
                                (.properties[] | select(.name == "spdx:license-concluded") | .value)
                            else
                                null
                            end
                        ) //
                        (
                            # Third: Try SPDX properties for license-declared
                            if (.properties | length) > 0 then
                                (.properties[] | select(.name == "spdx:license-declared") | .value)
                            else
                                null
                            end
                        ) //
                        # Final fallback
                        "unknown"
                    )
                ] | @tsv
            ' "$sbom_file" > "$data_file"
            ;;
        "spdxjson")
            # Extract from SPDX format
            jq -r '
                .packages[]? // empty |
                select(.name != null) |
                [
                    .name // "unknown",
                    .versionInfo // "unknown",
                    (.licenseConcluded // .licenseDeclared // "unknown")
                ] | @tsv
            ' "$sbom_file" > "$data_file"
            ;;
        *)
            log_error "Unsupported SBOM format for ClickHouse: $sbom_format"
            return 1
            ;;
    esac
    
    # Check if we have data to insert
    if [[ ! -s "$data_file" ]]; then
        log_warning "No component data found in SBOM"
        return
    fi

    # Map unknown licenses
    map_unknown_licenses "$data_file" "$mapped_data_file"
    
    local component_count=$(wc -l < "$mapped_data_file")
    log_info "Found $component_count components to insert (with license mapping applied)"
    
    # Insert data into ClickHouse
    if curl -s ${auth_params} \
           -H "Content-Type: text/tab-separated-values" \
           --data-binary "@$mapped_data_file" \
           "${clickhouse_url}/?query=INSERT%20INTO%20${CLICKHOUSE_DATABASE}.${table_name}%20(name,%20version,%20license)%20FORMAT%20TSV"; then
        log_success "Inserted $component_count components into ClickHouse table $table_name"
        return 0
    else
        log_error "Failed to insert data into ClickHouse"
        return 1
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
    validate_mend_env
    validate_wiz_env
    
    # Set defaults for optional variables
    local s3_key="${S3_KEY:-sbom.json}"
    local desired_format="${SBOM_FORMAT:-cyclonedx}"
    local merge_mode="${MERGE:-false}"
    local sbom_source="${SBOM_SOURCE:-github}"
    
    # Set up cleanup trap    
    trap cleanup EXIT

    # Temporary files
    if ! temp_dir=$(mktemp -d); then
        log_error "Failed to create temporary directory"
        exit 1
    fi

    if [[ "$merge_mode" == "true" ]]; then
        log_info "Running in MERGE mode - merging all CycloneDX SBOMs from S3"
        
        local merged_sbom="$temp_dir/merged_sbom.json"

        # Merge all CycloneDX SBOMs from S3
        merge_cyclonedx_sboms "$merged_sbom"
        
        # Validate the merged file
        if ! jq . "$merged_sbom" > /dev/null 2>&1; then
            log_error "Merged CycloneDX SBOM is not valid JSON"
            exit 1
        fi
        
        # Upload merged SBOM back to S3
        upload_to_s3 "$merged_sbom" "$S3_BUCKET" "$s3_key"
        
        log_success "SBOM merging and upload completed successfully!"
        log_info "Merged SBOM available at: s3://$S3_BUCKET/$s3_key"

        # ClickHouse operations
        if [[ -n "${CLICKHOUSE_URL:-}" ]]; then
            local table_name=$(echo "$s3_key" | sed 's|\.json|_merged|g' | tr '[:upper:]' '[:lower:]')
            log_info "Starting ClickHouse operations for table: $table_name"
            # Setup table with error handling
            if ! setup_clickhouse_table "$table_name"; then
                log_error "ClickHouse table setup failed, skipping data insertion"
                exit 1
            else
                # Insert SBOM data into ClickHouse
                if ! insert_sbom_data "$merged_sbom" "$table_name" "$desired_format"; then
                    log_error "Failed to insert SBOM data into ClickHouse"
                    exit 1
                else
                    log_info "Component data available in ClickHouse table: ${CLICKHOUSE_DATABASE}.${table_name}"
                    log_success "ClickHouse operations completed successfully!"
                fi
            fi
        fi
        exit 0
    else
        log_info "Running in NORMAL mode - processing SBOM from $sbom_source"

        local original_sbom="$temp_dir/original_sbom.json"
        local extracted_sbom="$temp_dir/extracted_sbom.json"
        local fixed_sbom="$temp_dir/fixed_sbom.json"
        local processed_sbom="$temp_dir/processed_sbom.json"
    
        # Download SBOM based on source
        case "$sbom_source" in
            "github")
                log_info "Downloading SBOM from GitHub"
                download_sbom "$REPOSITORY" "$original_sbom"
                ;;
            "mend")
                log_info "Downloading SBOM from Mend"
                request_mend_sbom_export "$original_sbom"
                ;;
            "wiz")
                log_info "Downloading SBOM from Wiz"
                download_wiz_report "$original_sbom"
                ;;
            *)
                log_error "Unsupported SBOM source: $sbom_source"
                log_error "Supported sources: github, mend"
                exit 1
                ;;
        esac

        # Extract SBOM from wrapper if needed
        extract_sbom_from_wrapper "$original_sbom" "$extracted_sbom"

        # Detect format
        local detected_format
        detected_format=$(detect_sbom_format "$extracted_sbom")
        log_info "Detected SBOM format: $detected_format"

        # Fix SPDX compatibility issues if needed
        if [[ "$detected_format" == "spdxjson" ]]; then
            fix_spdx_compatibility "$extracted_sbom" "$fixed_sbom"
            convert_sbom "$fixed_sbom" "$processed_sbom" "$detected_format" "$desired_format"
        else
            convert_sbom "$extracted_sbom" "$processed_sbom" "$detected_format" "$desired_format"
        fi
    
        # Validate the converted file
        if ! jq . "$processed_sbom" > /dev/null 2>&1; then
            log_error "Generated CycloneDX SBOM is not valid JSON"
            exit 1
        fi
    
        # Upload to S3
        upload_to_s3 "$processed_sbom" "$S3_BUCKET" "$s3_key"

        log_success "SBOM processing completed successfully!"
        log_info "SBOM available at: s3://$S3_BUCKET/$s3_key"

        # ClickHouse operations
        if [[ -n "${CLICKHOUSE_URL:-}" ]]; then
            local table_name
            case "$sbom_source" in
                "github")
                    table_name=$(echo "$REPOSITORY" | sed 's|[^a-zA-Z0-9]|_|g' | tr '[:upper:]' '[:lower:]')
                    ;;
                "mend")
                    table_name="mend_$(echo "${MEND_PROJECT_UUID:-${MEND_PRODUCT_UUID:-${MEND_ORG_SCOPE_UUID}}}" | sed 's|[^a-zA-Z0-9]|_|g' | tr '[:upper:]' '[:lower:]')"
                    ;;
                "wiz")
                    table_name="wiz_$(echo "${WIZ_REPORT_ID}" | sed 's|[^a-zA-Z0-9]|_|g' | tr '[:upper:]' '[:lower:]')"
                    ;;
            esac
            log_info "Starting ClickHouse operations for table: $table_name"
            # Setup table with error handling
            if ! setup_clickhouse_table "$table_name"; then
                log_error "ClickHouse table setup failed, skipping data insertion"
                exit 1
            else
                # Insert SBOM data into ClickHouse
                if ! insert_sbom_data "$processed_sbom" "$table_name" "$desired_format"; then
                    log_error "Failed to insert SBOM data into ClickHouse"
                    exit 1
                else
                    log_info "Component data available in ClickHouse table: ${CLICKHOUSE_DATABASE}.${table_name}"
                    log_success "ClickHouse operations completed successfully!"
                fi
            fi
        fi
    fi
}

# Run main function
main "$@"
