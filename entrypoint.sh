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
    local required_vars=("AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "S3_BUCKET")

    # Add REPOSITORY requirement only if not in merge mode
    if [[ "${MERGE:-false}" != "true" ]]; then
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
    
    # List all JSON files in the S3 bucket
    log_info "Listing CycloneDX SBOMs in S3 bucket..."
    local s3_files
    
    # Debug: Show raw S3 ls output
    log_info "Raw S3 listing for bucket: $S3_BUCKET"
    if ! aws s3 ls "s3://$S3_BUCKET" --recursive; then
        log_error "Failed to list files in S3 bucket: $S3_BUCKET"
        log_error "Check bucket name and AWS permissions"
        exit 1
    fi
    
    # Extract JSON files
    if ! s3_files=$(aws s3 ls "s3://$S3_BUCKET" --recursive | grep '\.json
    
    # Download and validate CycloneDX SBOMs
    local cyclonedx_files=()
    local file_count=0
    local total_files=0
    
    while IFS= read -r s3_key; do
        [[ -z "$s3_key" ]] && continue
        ((total_files++))
        
        local filename=$(basename "$s3_key")
        local local_file="$download_dir/$filename"

        log_info "Downloading ($total_files): s3://$S3_BUCKET/$s3_key"

        if aws s3 cp "s3://$S3_BUCKET/$s3_key" "$local_file"; then
            # Check if it's a valid CycloneDX SBOM
            log_info "Validating CycloneDX format for: $filename"

            # First check if it's valid JSON
            if ! jq . "$local_file" > /dev/null 2>&1; then
                log_warning "Skipping $filename - not valid JSON"
                continue
            fi

            # Check if it has bomFormat field
            local bom_format
            bom_format=$(jq -r '.bomFormat // "missing"' "$local_file" 2>/dev/null)
            log_info "File $filename has bomFormat: $bom_format"

            # Check if it's CycloneDX
            if [[ "$bom_format" == "CycloneDX" ]]; then
                cyclonedx_files+=("$local_file")
                ((file_count++))
                log_success "Valid CycloneDX SBOM: $filename"
            else
                log_warning "Skipping $filename - bomFormat is '$bom_format', not 'CycloneDX'"
                
                # Debug: Show first few lines of the file
                log_info "First 200 characters of $filename:"
                head -c 200 "$local_file" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g'
                echo ""
            fi
        else
            log_warning "Failed to download: $s3_key"
        fi
    done <<< "$s3_files"

    log_info "Downloaded $total_files files, found $file_count valid CycloneDX SBOMs"

    if [[ $file_count -eq 0 ]]; then
        log_error "No valid CycloneDX SBOMs found in S3 bucket"
        log_error "Check that your S3 bucket contains CycloneDX format SBOMs"
        exit 1
    fi
    
    log_info "Found $file_count CycloneDX SBOMs to merge"
    
    # Create the merged SBOM structure
    log_info "Creating merged CycloneDX SBOM..."
    
    # Start with the first SBOM as base
    local base_sbom="${cyclonedx_files[0]}"
    cp "$base_sbom" "$output_file"
    
    # Extract metadata from base SBOM
    local merged_metadata
    merged_metadata=$(jq '{
        bomFormat: .bomFormat,
        specVersion: .specVersion,
        serialNumber: ("urn:uuid:" + (now | tostring | @base64 | .[0:8] + "-" + .[8:12] + "-" + .[12:16] + "-" + .[16:20] + "-" + .[20:32])),
        version: 1,
        metadata: {
            timestamp: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
            tools: [{
                vendor: "ClickBOM",
                name: "cyclonedx-merge", 
                version: "1.0.0"
            }],
            component: {
                type: "application",
                name: "merged-sbom",
                version: "1.0.0"
            }
        }
    }' <<< '{}')
    
    # Merge all components from all SBOMs
    local all_components="$temp_dir/all_components.json"
    
    # Collect all components
    for sbom_file in "${cyclonedx_files[@]}"; do
        jq -r '.components[]? // empty' "$sbom_file" 2>/dev/null || true
    done | jq -s '.' > "$all_components"
    
    # Remove duplicates based on name+version combination
    local unique_components="$temp_dir/unique_components.json"
    jq 'unique_by(.name + "@" + (.version // "unknown"))' "$all_components" > "$unique_components"
    
    # Create final merged SBOM
    jq --slurpfile meta <(echo "$merged_metadata") \
       --slurpfile comps "$unique_components" \
       '$meta[0] + {components: $comps[0]}' <<< '{}' > "$output_file"
    
    # Validate the merged SBOM
    if ! jq . "$output_file" > /dev/null 2>&1; then
        log_error "Generated merged SBOM is not valid JSON"
        exit 1
    fi
    
    local component_count
    component_count=$(jq '.components | length' "$output_file")
    
    log_success "Successfully merged $file_count SBOMs into one with $component_count unique components"
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
    
    # Set defaults for optional variables
    local s3_key="${S3_KEY:-sbom.json}"
    local desired_format="${SBOM_FORMAT:-cyclonedx}"
    local merge_mode="${MERGE:-false}"
    
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
        exit 0
    else
        log_info "Running in NORMAL mode - processing GitHub SBOM"

        local original_sbom="$temp_dir/original_sbom.json"
        local extracted_sbom="$temp_dir/extracted_sbom.json"
        local fixed_sbom="$temp_dir/fixed_sbom.json"
        local processed_sbom="$temp_dir/processed_sbom.json"
    
        # Download SBOM
        download_sbom "$REPOSITORY" "$original_sbom"

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

        # ClickHouse operations (only in normal mode)
        if [[ -n "${CLICKHOUSE_URL:-}" ]]; then
            local table_name=$(echo "$REPOSITORY" | sed 's|[^a-zA-Z0-9]|_|g' | tr '[:upper:]' '[:lower:]')
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
