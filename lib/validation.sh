#!/bin/bash
# Environment validation functions

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

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
