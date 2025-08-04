#!/bin/bash
# SBOM format detection, conversion, and processing

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

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
