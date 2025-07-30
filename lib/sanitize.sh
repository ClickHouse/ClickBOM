#!/bin/bash
# Sanitize input to prevent command injection and other vulnerabilities

# Sanitize general string inputs - remove potentially dangerous characters
sanitize_string() {
    local input="$1"
    local max_length="${2:-1000}"  # Default max length of 1000 characters
    
    # Remove null bytes, control characters, and limit length
    local sanitized
    sanitized=$(echo "$input" | tr -d '\0' | tr -d '\001-\037' | tr -d '\177-\377' | cut -c1-"$max_length")
    
    # Remove potentially dangerous patterns
    sanitized=$(echo "$sanitized" | sed 's/[$(){}|;&<>@\[\]]//g' | tr -d '`')
    
    echo "$sanitized"
}

# Sanitize repository names (owner/repo format)
sanitize_repository() {
    local repo="$1"
    
    # Repository should only contain alphanumeric, hyphens, underscores, dots, and forward slash
    local sanitized
    sanitized=$(echo "$repo" | sed 's/[^a-zA-Z0-9._/-]//g')
    
    # Validate format: should be owner/repo
    if [[ ! "$sanitized" =~ ^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$ ]]; then
        log_error "Invalid repository format: $repo"
        log_error "Repository must be in 'owner/repo' format with alphanumeric characters, dots, hyphens, and underscores only"
        exit 1
    fi
    
    echo "$sanitized"
}

# Sanitize URLs - validate format and allowed protocols
sanitize_url() {
    local url="$1"
    local url_type="${2:-general}"  # general, clickhouse, mend, wiz
    
    # Remove null bytes and control characters
    local sanitized
    sanitized=$(echo "$url" | tr -d '\0' | tr -d '\001-\037' | tr -d '\177-\377')
    
    # Validate URL format and allowed protocols
    case "$url_type" in
        "clickhouse")
            if [[ ! "$sanitized" =~ ^https?://[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]+)?/?$ ]]; then
                log_error "Invalid ClickHouse URL format: $url"
                log_error "ClickHouse URL must be HTTP/HTTPS with valid hostname"
                exit 1
            fi
            ;;
        "mend")
            if [[ ! "$sanitized" =~ ^https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$ ]]; then
                log_error "Invalid Mend URL format: $url"
                log_error "Mend URL must be HTTPS with valid domain"
                exit 1
            fi
            ;;
        "wiz")
            if [[ ! "$sanitized" =~ ^https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$ ]]; then
                log_error "Invalid Wiz URL format: $url"
                log_error "Wiz URL must be HTTPS with valid domain"
                exit 1
            fi
            ;;
        *)
            if [[ ! "$sanitized" =~ ^https?://[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]+)?(/.*)?$ ]]; then
                log_error "Invalid URL format: $url"
                log_error "URL must be HTTP/HTTPS with valid hostname"
                exit 1
            fi
            ;;
    esac
    
    echo "$sanitized"
}

# Sanitize S3 bucket names
sanitize_s3_bucket() {
    local bucket="$1"
    
    # S3 bucket names have specific rules
    local sanitized
    sanitized=$(echo "$bucket" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.-]//g')
    
    # Validate S3 bucket naming rules
    if [[ ! "$sanitized" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]]; then
        log_error "Invalid S3 bucket name: $bucket"
        log_error "S3 bucket names must be 3-63 characters, lowercase, and contain only letters, numbers, dots, and hyphens"
        exit 1
    fi
    
    # Additional S3 bucket rules
    if [[ "$sanitized" == *.* ]]; then
        # If contains dots, validate it's not IP-like
        if [[ "$sanitized" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            log_error "S3 bucket name cannot be formatted as IP address: $bucket"
            exit 1
        fi
    fi
    
    echo "$sanitized"
}

# Sanitize S3 key
sanitize_s3_key() {
    local key="$1"
    
    # S3 keys can contain most characters but we'll be restrictive for security
    local sanitized
    sanitized=$(echo "$key" | sed 's/[^a-zA-Z0-9._/-]//g')
    
    # Prevent path traversal attempts
    sanitized=$(echo "$sanitized" | sed 's/\.\.//g' | sed 's/\/\+/\//g')
    
    # Remove leading/trailing slashes
    sanitized=$(echo "$sanitized" | sed 's/^\/*//' | sed 's/\/*$//')
    
    if [[ -z "$sanitized" ]]; then
        log_error "Invalid S3 key: $key"
        log_error "S3 key must contain valid characters and cannot be empty"
        exit 1
    fi
    
    echo "$sanitized"
}

# Sanitize UUID format (for Mend/Wiz IDs)
sanitize_uuid() {
    local uuid="$1"
    local field_name="$2"
    
    # Remove any non-hex characters except hyphens
    local sanitized
    sanitized=$(echo "$uuid" | sed 's/[^a-fA-F0-9-]//g')
    
    # Validate UUID format (loose validation - some services use non-standard formats)
    if [[ ! "$sanitized" =~ ^[0-9a-fA-F]{8}-?([0-9a-fA-F]{4}-?){3}[0-9a-fA-F]{12}$ ]]; then
        log_error "Invalid UUID format for $field_name: $uuid"
        log_error "UUID must contain only hexadecimal characters and hyphens"
        exit 1
    fi
    
    echo "$sanitized"
}

# Sanitize email addresses
sanitize_email() {
    local email="$1"
    
    # Handle both literal escape sequences and actual control characters
    local sanitized="$email"
    
    # Remove literal escape sequences
    sanitized=$(echo "$sanitized" | sed 's/\\n//g; s/\\r//g; s/\\t//g; s/\\\\//g')
    
    # Remove actual control characters
    sanitized=$(echo "$sanitized" | tr -d '\n\r\t\001-\037\177-\377')
    
    # Remove other dangerous characters but keep email-valid ones (including +)
    sanitized=$(echo "$sanitized" | sed 's/[^a-zA-Z0-9@._+-]//g')
    
    # Basic email format validation (updated regex to allow + in local part)
    if [[ ! "$sanitized" =~ ^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log_error "Invalid email format: $email"
        log_error "Email must be in valid format: user@domain.com"
        exit 1
    fi
    
    echo "$sanitized"
}

# Sanitize database/table names
sanitize_database_name() {
    local name="$1"
    
    # Database names should only contain alphanumeric and underscores
    local sanitized
    sanitized=$(echo "$name" | sed 's/[^a-zA-Z0-9_]//g' | sed 's/^[0-9]/_&/')
    
    echo "$sanitized"
}

# Sanitize comma-separated patterns (for include/exclude)
sanitize_patterns() {
    local patterns="$1"
    
    if [[ -z "$patterns" ]]; then
        echo ""
        return
    fi
    
    # Split by comma and sanitize each pattern
    local sanitized_patterns=()
    IFS=',' read -ra pattern_array <<< "$patterns"
    
    for pattern in "${pattern_array[@]}"; do
        # Trim whitespace
        pattern=$(echo "$pattern" | xargs)
        
        # Remove dangerous characters but keep wildcards
        local sanitized_pattern
        sanitized_pattern=$(echo "$pattern" | sed 's/[^a-zA-Z0-9.*_-]//g')
        
        if [[ -n "$sanitized_pattern" ]]; then
            sanitized_patterns+=("$sanitized_pattern")
        fi
    done
    
    # Join back with commas
    local result
    result=$(IFS=','; echo "${sanitized_patterns[*]}")
    echo "$result"
}

# Sanitize numeric values
sanitize_numeric() {
    local value="$1"
    local field_name="$2"
    local min_val="${3:-0}"
    local max_val="${4:-999999}"
    
    # Remove non-numeric characters
    local sanitized
    sanitized=$(echo "$value" | sed 's/[^0-9]//g')
    
    # Validate it's a number
    if [[ ! "$sanitized" =~ ^[0-9]+$ ]]; then
        log_error "Invalid numeric value for $field_name: $value"
        log_error "Value must be a positive integer"
        exit 1
    fi

    # Check range
    if (( sanitized < min_val )) || (( sanitized > max_val )); then
        log_error "Numeric value for $field_name out of range: $sanitized"
        log_error "Value must be between $min_val and $max_val"
        exit 1
    fi
    
    echo "$sanitized"
}

# Main sanitization function - sanitizes all environment variables
sanitize_inputs() {
    log_debug "Sanitizing input parameters..."

    # GitHub inputs
    if [[ -n "${REPOSITORY:-}" ]]; then
        REPOSITORY=$(sanitize_repository "$REPOSITORY")
        log_debug "Sanitized REPOSITORY: $REPOSITORY"
    fi
    
    # Mend inputs
    if [[ -n "${MEND_EMAIL:-}" ]]; then
        MEND_EMAIL=$(sanitize_email "$MEND_EMAIL")
        log_debug "Sanitized MEND_EMAIL: $MEND_EMAIL"
    fi
    
    if [[ -n "${MEND_BASE_URL:-}" ]]; then
        MEND_BASE_URL=$(sanitize_url "$MEND_BASE_URL" "mend")
        log_debug "Sanitized MEND_BASE_URL: $MEND_BASE_URL"
    fi
    
    if [[ -n "${MEND_ORG_UUID:-}" ]]; then
        MEND_ORG_UUID=$(sanitize_uuid "$MEND_ORG_UUID" "MEND_ORG_UUID")
        log_debug "Sanitized MEND_ORG_UUID: $MEND_ORG_UUID"
    fi
    
    if [[ -n "${MEND_USER_KEY:-}" ]]; then
        MEND_USER_KEY=$(sanitize_string "$MEND_USER_KEY" 500)
        log_debug "Sanitized MEND_USER_KEY: [REDACTED]"
    fi
    
    if [[ -n "${MEND_PROJECT_UUID:-}" ]]; then
        MEND_PROJECT_UUID=$(sanitize_uuid "$MEND_PROJECT_UUID" "MEND_PROJECT_UUID")
        log_debug "Sanitized MEND_PROJECT_UUID: $MEND_PROJECT_UUID"
    fi
    
    if [[ -n "${MEND_PRODUCT_UUID:-}" ]]; then
        MEND_PRODUCT_UUID=$(sanitize_uuid "$MEND_PRODUCT_UUID" "MEND_PRODUCT_UUID")
        log_debug "Sanitized MEND_PRODUCT_UUID: $MEND_PRODUCT_UUID"
    fi
    
    if [[ -n "${MEND_ORG_SCOPE_UUID:-}" ]]; then
        MEND_ORG_SCOPE_UUID=$(sanitize_uuid "$MEND_ORG_SCOPE_UUID" "MEND_ORG_SCOPE_UUID")
        log_debug "Sanitized MEND_ORG_SCOPE_UUID: $MEND_ORG_SCOPE_UUID"
    fi
    
    if [[ -n "${MEND_PROJECT_UUIDS:-}" ]]; then
        # Split by comma and sanitize each UUID
        local sanitized_uuids=()
        IFS=',' read -ra uuid_array <<< "$MEND_PROJECT_UUIDS"
        for uuid in "${uuid_array[@]}"; do
            uuid=$(echo "$uuid" | xargs)  # trim whitespace
            if [[ -n "$uuid" ]]; then
                sanitized_uuids+=($(sanitize_uuid "$uuid" "MEND_PROJECT_UUIDS"))
            fi
        done
        MEND_PROJECT_UUIDS=$(IFS=','; echo "${sanitized_uuids[*]}")
        log_debug "Sanitized MEND_PROJECT_UUIDS: $MEND_PROJECT_UUIDS"
    fi
    
    if [[ -n "${MEND_MAX_WAIT_TIME:-}" ]]; then
        MEND_MAX_WAIT_TIME=$(sanitize_numeric "$MEND_MAX_WAIT_TIME" "MEND_MAX_WAIT_TIME" 60 7200)
        log_debug "Sanitized MEND_MAX_WAIT_TIME: $MEND_MAX_WAIT_TIME"
    fi
    
    if [[ -n "${MEND_POLL_INTERVAL:-}" ]]; then
        MEND_POLL_INTERVAL=$(sanitize_numeric "$MEND_POLL_INTERVAL" "MEND_POLL_INTERVAL" 10 300)
        log_debug "Sanitized MEND_POLL_INTERVAL: $MEND_POLL_INTERVAL"
    fi
    
    # Wiz inputs
    if [[ -n "${WIZ_AUTH_ENDPOINT:-}" ]]; then
        WIZ_AUTH_ENDPOINT=$(sanitize_url "$WIZ_AUTH_ENDPOINT" "wiz")
        log_debug "Sanitized WIZ_AUTH_ENDPOINT: $WIZ_AUTH_ENDPOINT"
    fi
    
    if [[ -n "${WIZ_API_ENDPOINT:-}" ]]; then
        WIZ_API_ENDPOINT=$(sanitize_url "$WIZ_API_ENDPOINT" "wiz")
        log_debug "Sanitized WIZ_API_ENDPOINT: $WIZ_API_ENDPOINT"
    fi
    
    if [[ -n "${WIZ_CLIENT_ID:-}" ]]; then
        WIZ_CLIENT_ID=$(sanitize_string "$WIZ_CLIENT_ID" 200)
        log_debug "Sanitized WIZ_CLIENT_ID: [REDACTED]"
    fi
    
    if [[ -n "${WIZ_CLIENT_SECRET:-}" ]]; then
        WIZ_CLIENT_SECRET=$(sanitize_string "$WIZ_CLIENT_SECRET" 500)
        log_debug "Sanitized WIZ_CLIENT_SECRET: [REDACTED]"
    fi
    
    if [[ -n "${WIZ_REPORT_ID:-}" ]]; then
        WIZ_REPORT_ID=$(sanitize_string "$WIZ_REPORT_ID" 200)
        log_debug "Sanitized WIZ_REPORT_ID: $WIZ_REPORT_ID"
    fi
    
    # AWS inputs
    if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]]; then
        AWS_ACCESS_KEY_ID=$(sanitize_string "$AWS_ACCESS_KEY_ID" 100)
        log_debug "Sanitized AWS_ACCESS_KEY_ID: [REDACTED]"
    fi
    
    if [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
        AWS_SECRET_ACCESS_KEY=$(sanitize_string "$AWS_SECRET_ACCESS_KEY" 500)
        log_debug "Sanitized AWS_SECRET_ACCESS_KEY: [REDACTED]"
    fi
    
    if [[ -n "${AWS_DEFAULT_REGION:-}" ]]; then
        AWS_DEFAULT_REGION=$(sanitize_string "$AWS_DEFAULT_REGION" 50)
        log_debug "Sanitized AWS_DEFAULT_REGION: $AWS_DEFAULT_REGION"
    fi
    
    if [[ -n "${S3_BUCKET:-}" ]]; then
        S3_BUCKET=$(sanitize_s3_bucket "$S3_BUCKET")
        log_debug "Sanitized S3_BUCKET: $S3_BUCKET"
    fi
    
    if [[ -n "${S3_KEY:-}" ]]; then
        S3_KEY=$(sanitize_s3_key "$S3_KEY")
        log_debug "Sanitized S3_KEY: $S3_KEY"
    fi
    
    # ClickHouse inputs
    if [[ -n "${CLICKHOUSE_URL:-}" ]]; then
        CLICKHOUSE_URL=$(sanitize_url "$CLICKHOUSE_URL" "clickhouse")
        log_debug "Sanitized CLICKHOUSE_URL: $CLICKHOUSE_URL"
    fi
    
    if [[ -n "${CLICKHOUSE_DATABASE:-}" ]]; then
        CLICKHOUSE_DATABASE=$(sanitize_database_name "$CLICKHOUSE_DATABASE")
        log_debug "Sanitized CLICKHOUSE_DATABASE: $CLICKHOUSE_DATABASE"
    fi
    
    if [[ -n "${CLICKHOUSE_USERNAME:-}" ]]; then
        CLICKHOUSE_USERNAME=$(sanitize_string "$CLICKHOUSE_USERNAME" 100)
        log_debug "Sanitized CLICKHOUSE_USERNAME: $CLICKHOUSE_USERNAME"
    fi
    
    if [[ -n "${CLICKHOUSE_PASSWORD:-}" ]]; then
        CLICKHOUSE_PASSWORD=$(sanitize_string "$CLICKHOUSE_PASSWORD" 500)
        log_debug "Sanitized CLICKHOUSE_PASSWORD: [REDACTED]"
    fi
    
    # General inputs
    if [[ -n "${SBOM_SOURCE:-}" ]]; then
        if [[ ! "$SBOM_SOURCE" =~ ^(github|mend|wiz)$ ]]; then
            log_error "Invalid SBOM_SOURCE: $SBOM_SOURCE"
            log_error "SBOM_SOURCE must be one of: github, mend, wiz"
            exit 1
        fi
        log_debug "Validated SBOM_SOURCE: $SBOM_SOURCE"
    fi
    
    if [[ -n "${SBOM_FORMAT:-}" ]]; then
        if [[ ! "$SBOM_FORMAT" =~ ^(cyclonedx|spdxjson)$ ]]; then
            log_error "Invalid SBOM_FORMAT: $SBOM_FORMAT"
            log_error "SBOM_FORMAT must be one of: cyclonedx, spdxjson"
            exit 1
        fi
        log_debug "Validated SBOM_FORMAT: $SBOM_FORMAT"
    fi
    
    if [[ -n "${MERGE:-}" ]]; then
        if [[ ! "$MERGE" =~ ^(true|false)$ ]]; then
            log_error "Invalid MERGE value: $MERGE"
            log_error "MERGE must be either 'true' or 'false'"
            exit 1
        fi
        log_debug "Validated MERGE: $MERGE"
    fi
    
    if [[ -n "${INCLUDE:-}" ]]; then
        INCLUDE=$(sanitize_patterns "$INCLUDE")
        log_debug "Sanitized INCLUDE: $INCLUDE"
    fi
    
    if [[ -n "${EXCLUDE:-}" ]]; then
        EXCLUDE=$(sanitize_patterns "$EXCLUDE")
        log_debug "Sanitized EXCLUDE: $EXCLUDE"
    fi
    
    # Sanitize tokens (GitHub token, etc.) - just remove dangerous characters
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        GITHUB_TOKEN=$(sanitize_string "$GITHUB_TOKEN" 1000)
        log_debug "Sanitized GITHUB_TOKEN: [REDACTED]"
    fi
    
    log_success "Input sanitization completed successfully"
}