#!/bin/bash

set -euo pipefail

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source all library files
source "$SCRIPT_DIR/lib/sanitize.sh"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/validation.sh"
source "$SCRIPT_DIR/lib/github.sh"
source "$SCRIPT_DIR/lib/mend.sh"
source "$SCRIPT_DIR/lib/wiz.sh"
source "$SCRIPT_DIR/lib/sbom-processing.sh"

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

# Extract source document reference from an SBOM
extract_sbom_source_reference() {
    local sbom_file="$1"
    local fallback_name="$2"  # Fallback name (e.g., filename)
    
    log_debug "Extracting source reference from $(basename "$sbom_file")"
    
    # Try multiple strategies to extract the source reference
    local source_ref=""
    
    # Strategy 1: Check for spdx:document:name in properties (GitHub SBOMs)
    if source_ref=$(jq -r '.metadata.properties[]? | select(.name == "spdx:document:name") | .value' "$sbom_file" 2>/dev/null); then
        if [[ -n "$source_ref" && "$source_ref" != "null" ]]; then
            log_debug "Found SPDX document name: $source_ref"
            echo "$source_ref"
            return 0
        fi
    fi
    
    # Strategy 2: Check metadata.component.name (Wiz/Mend SBOMs)
    if source_ref=$(jq -r '.metadata.component.name // empty' "$sbom_file" 2>/dev/null); then
        if [[ -n "$source_ref" && "$source_ref" != "null" ]]; then
            log_debug "Found component name: $source_ref"
            echo "$source_ref"
            return 0
        fi
    fi
    
    # Strategy 3: Check metadata.component.bom-ref (Mend SBOMs)
    if source_ref=$(jq -r '.metadata.component."bom-ref" // empty' "$sbom_file" 2>/dev/null); then
        if [[ -n "$source_ref" && "$source_ref" != "null" ]]; then
            log_debug "Found bom-ref: $source_ref"
            echo "$source_ref"
            return 0
        fi
    fi
    
    # Strategy 4: Check top-level name field
    if source_ref=$(jq -r '.name // empty' "$sbom_file" 2>/dev/null); then
        if [[ -n "$source_ref" && "$source_ref" != "null" ]]; then
            log_debug "Found top-level name: $source_ref"
            echo "$source_ref"
            return 0
        fi
    fi
    
    # Strategy 5: Check metadata.tools for document name hints
    if source_ref=$(jq -r '.metadata.tools[]?.name // empty' "$sbom_file" 2>/dev/null | grep -v "GitHub.com-Dependency\|protobom\|CycloneDX\|cyclonedx-merge" | head -1); then
        if [[ -n "$source_ref" && "$source_ref" != "null" ]]; then
            log_debug "Found tool name hint: $source_ref"
            echo "$source_ref"
            return 0
        fi
    fi
    
    # Strategy 6: Use fallback (usually filename without extension)
    if [[ -n "$fallback_name" ]]; then
        local clean_fallback=$(basename "$fallback_name" .json)
        log_debug "Using fallback name: $clean_fallback"
        echo "$clean_fallback"
        return 0
    fi
    
    # Final fallback
    log_warning "Could not extract source reference, using 'unknown'"
    echo "unknown"
    return 0
}

# Enhanced component collection with source tracking
collect_components_with_source() {
    local sbom_file="$1"
    local source_ref="$2"
    local output_file="$3"
    
    log_debug "Collecting components from $(basename "$sbom_file") with source: $source_ref"
    
    # Extract components and add source reference to each
    if jq --arg source "$source_ref" '
        .components[]? // empty |
        . + {"source": $source}
    ' "$sbom_file" > "$output_file" 2>/dev/null; then
        local component_count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
        log_debug "Collected $component_count components with source: $source_ref"
        return 0
    else
        log_warning "Failed to collect components from $(basename "$sbom_file")"
        touch "$output_file"  # Create empty file
        return 1
    fi
}

# Function to check if a filename matches any pattern in a list
matches_pattern() {
    local filename="$1"
    local patterns="$2"
    
    # If no patterns provided, return false (no match)
    if [[ -z "$patterns" ]]; then
        return 1
    fi
    
    # Split patterns by comma and check each one
    IFS=',' read -ra pattern_array <<< "$patterns"
    for pattern in "${pattern_array[@]}"; do
        # Trim whitespace
        pattern=$(echo "$pattern" | xargs)
        
        # Check if filename matches the pattern using bash pattern matching
        if [[ "$filename" == $pattern ]]; then
            return 0
        fi
    done
    
    return 1
}

# Function to filter files based on include/exclude patterns
filter_files() {
    local files_input="$1"
    local include_patterns="${INCLUDE:-}"
    local exclude_patterns="${EXCLUDE:-}"
    
    local filtered_files=""
    
    # Process each file
    while IFS= read -r file; do
        # Skip empty lines
        [[ -z "$file" ]] && continue
        
        local filename=$(basename "$file")
        local should_include=true
        
        # If include patterns are specified, file must match at least one include pattern
        if [[ -n "$include_patterns" ]]; then
            if matches_pattern "$filename" "$include_patterns"; then
                should_include=true
            else
                should_include=false
            fi
        else
            # No include patterns specified, so include all files by default
            should_include=true
        fi
        
        # If exclude patterns are specified and file matches, exclude it
        if [[ "$should_include" == "true" && -n "$exclude_patterns" ]]; then
            if matches_pattern "$filename" "$exclude_patterns"; then
                should_include=false
            fi
        fi
        
        # Add to filtered list if it should be included
        if [[ "$should_include" == "true" ]]; then
            if [[ -n "$filtered_files" ]]; then
                filtered_files="$filtered_files"$'\n'"$file"
            else
                filtered_files="$file"
            fi
        fi
    done <<< "$files_input"
    
    echo "$filtered_files"
}

# Download all CycloneDX SBOMs from S3 bucket and merge them
merge_cyclonedx_sboms() {
    local output_file="$1"
    
    log_info "Merging all CycloneDX SBOMs from S3 bucket: $S3_BUCKET with source tracking"
    
    # Log include/exclude patterns if specified
    if [[ -n "${INCLUDE:-}" ]]; then
        log_info "Include patterns: ${INCLUDE}"
    fi
    if [[ -n "${EXCLUDE:-}" ]]; then
        log_info "Exclude patterns: ${EXCLUDE}"
    fi
    
    # Create temporary directory for downloaded SBOMs
    local download_dir="$temp_dir/sboms"
    mkdir -p "$download_dir"
    
    # List all JSON files in the S3 bucket
    local s3_files
    
    # Debug: Show raw S3 ls output
    log_debug "Raw S3 listing for bucket: $S3_BUCKET"
    if [[ "${DEBUG:-false}" == "true" ]]; then
        if ! aws s3 ls "s3://$S3_BUCKET" --recursive; then
            log_error "Failed to list files in S3 bucket: $S3_BUCKET"
            log_error "Check bucket name and AWS permissions"
            exit 1
        fi
    fi

    # Extract JSON files
    log_info "Extracting JSON file paths..."
    
    # Debug: Show the filtering process step by step
    local all_files
    all_files=$(aws s3 ls "s3://$S3_BUCKET" --recursive | awk '{print $4}' || true)
    log_info "All files found: $(echo "$all_files" | wc -l) files"
    
    local json_files
    json_files=$(echo "$all_files" | grep '\.json$' || true)
    log_info "JSON files found: $(echo "$json_files" | wc -l) files"
        
    # Also exclude the target S3_KEY file to avoid processing the merged output
    local s3_key_basename=$(basename "${S3_KEY:-sbom.json}")
    s3_files=$(echo "$json_files" | grep -v "^${s3_key_basename}$" || true)
    log_info "JSON files after excluding target file ($s3_key_basename): $(echo "$s3_files" | wc -l) files"
    
    # Apply include/exclude filters
    if [[ -n "${INCLUDE:-}" ]] || [[ -n "${EXCLUDE:-}" ]]; then
        log_info "Applying include/exclude filters..."
        s3_files=$(filter_files "$s3_files")
        log_info "Files after filtering: $(echo "$s3_files" | wc -l) files"
    fi
    
    # Debug: Show what files we're going to process
    log_info "Files to process:"
    echo "$s3_files" | while IFS= read -r file; do
        [[ -n "$file" ]] && log_info "  - $file"
    done

    if [[ -z "$s3_files" ]] || [[ "$(echo "$s3_files" | wc -l)" -eq 0 ]]; then
        log_error "No JSON files found in S3 bucket after filtering"
        log_error "Check your include/exclude patterns and ensure there are valid files"
        if [[ -n "${INCLUDE:-}" ]]; then
            log_error "Include patterns: ${INCLUDE}"
        fi
        if [[ -n "${EXCLUDE:-}" ]]; then
            log_error "Exclude patterns: ${EXCLUDE}"
        fi
        exit 1
    fi

    # Download and validate CycloneDX SBOMs with source tracking
    local cyclonedx_files=()
    local source_references=()  # Parallel array to track source references
    local file_count=0
    local total_files=0

    log_info "Starting download loop with source tracking..."

    local files_array=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && files_array+=("$line")
    done <<< "$s3_files"
    
    log_info "Processing ${#files_array[@]} files with source extraction..."
    
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

        log_debug "Downloading ($total_files/${#files_array[@]}): s3://$S3_BUCKET/$s3_key_to_merge"

        # Try to download the file
        if aws s3 cp "s3://$S3_BUCKET/$s3_key_to_merge" "$local_file"; then
            log_success "Downloaded: $filename"
            
            # Check if it's a valid CycloneDX SBOM
            log_debug "Validating CycloneDX format for: $filename"

            # First check if it's valid JSON
            if jq empty "$local_file" >/dev/null 2>&1; then
                log_debug "JSON validation passed for: $filename"
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
            
            log_debug "File $filename has bomFormat: $bom_format"

            # Check if it's CycloneDX (also check for metadata.component as backup)
            local is_cyclonedx=false
            
            if [[ "$bom_format" == "CycloneDX" ]]; then
                is_cyclonedx=true
            elif jq -e '.metadata.component' "$local_file" >/dev/null 2>&1; then
                is_cyclonedx=true
                log_info "Detected CycloneDX via metadata.component field"
            fi
            
            if [[ "$is_cyclonedx" == "true" ]]; then
                # Extract source reference before adding to processing list
                local source_ref
                source_ref=$(extract_sbom_source_reference "$local_file" "$filename")

                cyclonedx_files+=("$local_file")
                source_references+=("$source_ref")
                file_count=$((file_count + 1))
                log_success "Valid CycloneDX SBOM: $filename (source: $source_ref)"
            else
                log_warning "Skipping $filename - bomFormat is '$bom_format', not 'CycloneDX'"
                
                # Debug: Show structure of the file to understand why it's not recognized
                log_debug "File structure preview for $filename:"
                if [[ "${DEBUG:-false}" == "true" ]]; then
                    if jq -r 'keys[]' "$local_file" 2>/dev/null | head -5; then
                        echo "Keys shown above"
                    else
                        echo "Unable to read keys from file"
                    fi
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
        log_error "No valid CycloneDX SBOMs found in S3 bucket after filtering"
        log_error "Check that your S3 bucket contains CycloneDX format SBOMs"
        log_error "and that your include/exclude patterns are correct"
        
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

    log_info "Found $file_count CycloneDX SBOMs to merge with source tracking"

    # Create the merged SBOM structure
    log_info "Creating merged CycloneDX SBOM with source tracking..."
    
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
            "version": "1.0.9"
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
    
    # Collect all components from all SBOMs with source tracking
    log_info "Collecting components from all SBOMs..."
    local all_components="$temp_dir/all_components.json"
    
    # Initialize empty array
    echo "[]" > "$all_components"

    # Collect all components with source information
    for sbom_file in "${cyclonedx_files[@]}"; do
        local sbom_file="${cyclonedx_files[i]}"
        local source_ref="${source_references[i]}"

        local component_count
        component_count=$(jq '.components | length' "$sbom_file" 2>/dev/null) || component_count=0
        log_info "Processing $(basename "$sbom_file"): $component_count components (source: $source_ref)"

        # Extract components with source tracking
        if [[ "$component_count" -gt 0 ]]; then
            local temp_components="$temp_dir/temp_components_$(basename "$sbom_file").json"
            if collect_components_with_source "$sbom_file" "$source_ref" "$temp_components"; then
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
    
    # Remove duplicates based on name+version+purl combination
    log_info "Removing duplicate components (preserving source information)..."
    local unique_components="$temp_dir/unique_components.json"
    if jq 'unique_by((.name // "unknown") + "@" + (.version // "unknown") + "#" + (.purl // "") + "^" + (.source // "unknown"))' "$all_components" > "$unique_components"; then
        log_success "Deduplication completed with source preservation"
    else
        log_error "Failed to deduplicate components"
        exit 1
    fi
    
    # Create final merged SBOM
    log_info "Assembling final merged SBOM with source tracking..."
    if echo "$merged_metadata" | jq --slurpfile comps "$unique_components" '. + {components: $comps[0]}' > "$output_file"; then
        log_success "Final SBOM assembled with source tracking"
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
    
    log_success "Successfully merged $file_count SBOMs into one with $component_count unique components (with source tracking)"
    
    # Show a summary of what was merged with source information
    log_info "Merge summary with source tracking:"
    for i in "${!cyclonedx_files[@]}"; do
        local sbom_file="${cyclonedx_files[i]}"
        local source_ref="${source_references[i]}"
        local fname=$(basename "$sbom_file" .json)
        local comp_count
        comp_count=$(jq '.components | length' "$sbom_file" 2>/dev/null) || comp_count=0
        log_info "  - $fname: $comp_count components (source: $source_ref)"
    done
}

# Merge multiple local CycloneDX SBOMs into one
merge_local_cyclonedx_sboms() {
    local output_file="${!#}"  # Last argument is the output file
    local input_files=("${@:1:$#-1}")  # All arguments except the last one
    
    log_info "Merging ${#input_files[@]} local CycloneDX SBOMs with source tracking"
    
    # Create the merged SBOM structure
    log_info "Creating merged CycloneDX SBOM with source tracking..."
    
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
            "version": "1.0.9"
        }],
        "component": {
            "type": "application",
            "name": "wiz-merged-sbom",
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
    
    # Collect all components from all SBOMs with source tracking
    log_info "Collecting components from all SBOMs with source tracking..."
    local all_components="$temp_dir/wiz_all_components.json"
    
    # Initialize empty array
    echo "[]" > "$all_components"
    
    # Collect all components with source tracking from input files
    for sbom_file in "${input_files[@]}"; do
        # Extract source reference for this SBOM
        local source_ref
        source_ref=$(extract_sbom_source_reference "$sbom_file" "$(basename "$sbom_file")")
        
        local component_count
        component_count=$(jq '.components | length' "$sbom_file" 2>/dev/null) || component_count=0
        log_info "Processing $(basename "$sbom_file"): $component_count components (source: $source_ref)"
        
        # Extract components with source tracking
        if [[ "$component_count" -gt 0 ]]; then
            local temp_components="$temp_dir/wiz_temp_components_$(basename "$sbom_file").json"
            if collect_components_with_source "$sbom_file" "$source_ref" "$temp_components"; then
                # Merge with existing components
                if jq -s 'flatten' "$all_components" "$temp_components" > "$temp_dir/wiz_merged_temp.json"; then
                    mv "$temp_dir/wiz_merged_temp.json" "$all_components"
                else
                    log_warning "Failed to merge components from $(basename "$sbom_file")"
                fi
            else
                log_warning "Failed to extract components from $(basename "$sbom_file")"
            fi
        fi
    done
    
    # Remove duplicates based on name+version+purl+source combination
    log_info "Removing duplicate components (preserving source information)..."
    local unique_components="$temp_dir/wiz_unique_components.json"
    if jq 'unique_by((.name // "unknown") + "@" + (.version // "unknown") + "#" + (.purl // "") + "^" + (.source // "unknown"))' "$all_components" > "$unique_components"; then
        log_success "Deduplication completed with source preservation"
    else
        log_error "Failed to deduplicate components"
        exit 1
    fi
    
    # Create final merged SBOM
    log_info "Assembling final merged SBOM with source tracking..."
    if echo "$merged_metadata" | jq --slurpfile comps "$unique_components" '. + {components: $comps[0]}' > "$output_file"; then
        log_success "Final SBOM assembled with source tracking"
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
    
    log_success "Successfully merged ${#input_files[@]} SBOMs into one with $component_count unique components (with source tracking)"
    
    # Show a summary of what was merged with source information
    log_info "Merge summary with source tracking:"
    for sbom_file in "${input_files[@]}"; do
        local source_ref
        source_ref=$(extract_sbom_source_reference "$sbom_file" "$(basename "$sbom_file")")
        local fname=$(basename "$sbom_file" .json)
        local comp_count
        comp_count=$(jq '.components | length' "$sbom_file" 2>/dev/null) || comp_count=0
        log_info "  - $fname: $comp_count components (source: $source_ref)"
    done
}

# Check if table needs migration for source column
check_and_migrate_table() {
    local table_name="$1"
    local clickhouse_url="$2"
    local auth_params="$3"
    
    log_info "Checking if table $table_name needs migration for source column"
    
    # Check if source column exists
    local column_exists
    if column_exists=$(curl -s ${auth_params} --data "SELECT COUNT(*) FROM system.columns WHERE database='${CLICKHOUSE_DATABASE}' AND table='${table_name}' AND name='source'" "${clickhouse_url}"); then
        if [[ "$column_exists" == "0" ]]; then
            log_info "source column not found, migrating table: $table_name"
            
            # Add source column with default value
            local alter_sql="ALTER TABLE ${CLICKHOUSE_DATABASE}.${table_name} ADD COLUMN source LowCardinality(String) DEFAULT 'unknown'"
            
            if curl -s ${auth_params} --data "$alter_sql" "${clickhouse_url}"; then
                log_success "source column added to table $table_name"
                return 0
            else
                log_error "Failed to add source column to table $table_name"
                return 1
            fi
        else
            log_info "source column already exists in table $table_name"
            return 0
        fi
    else
        log_error "Failed to check column existence for table $table_name"
        return 1
    fi
}

# Set up ClickHouse table
setup_clickhouse_table() {
    local table_name="$1"
    
    log_info "Setting up ClickHouse table: $table_name"
    
    # Build ClickHouse URL
    local clickhouse_url="${CLICKHOUSE_URL}"
    local auth_params=""
    
    # Use basic auth if username and password are provided
    if [[ -n "${CLICKHOUSE_USERNAME:-}" ]] && [[ -n "${CLICKHOUSE_PASSWORD:-}" ]]; then
        auth_params="-u ${CLICKHOUSE_USERNAME}:${CLICKHOUSE_PASSWORD}"
        log_debug "Using basic auth with username: ${CLICKHOUSE_USERNAME}"
    elif [[ -n "${CLICKHOUSE_USERNAME:-}" ]]; then
        auth_params="-u ${CLICKHOUSE_USERNAME}:"
        log_debug "Using basic auth with username only: ${CLICKHOUSE_USERNAME}"
    else
        log_debug "Using no authentication"
    fi
    
    # Test connection first
    log_debug "Testing ClickHouse connection..."
    if [[ "${DEBUG:-false}" == "true" ]]; then
        if ! curl -s ${auth_params} --data "SELECT 1" "${clickhouse_url}" > /dev/null; then
            log_error "ClickHouse connection test failed"
            log_error "Please verify your ClickHouse credentials and URL"
            return 1
        fi
        log_success "ClickHouse connection successful"
    fi

    # Check if table exists
    local table_exists
    if table_exists=$(curl -s ${auth_params} --data "SELECT COUNT(*) FROM system.tables WHERE database='${CLICKHOUSE_DATABASE}' AND name='${table_name}'" "${clickhouse_url}"); then
        if [[ "$table_exists" == "1" ]]; then
            log_info "Table $table_name already exists"

            # Check and migrate table if needed
            if ! check_and_migrate_table "$table_name" "$clickhouse_url" "$auth_params"; then
                log_error "Table migration failed"
                return 1
            fi

            if [[ "${TRUNCATE_TABLE:-false}" == "true" ]]; then
                log_info "Truncating existing table: $table_name"
                if curl -s ${auth_params} --data "TRUNCATE TABLE ${CLICKHOUSE_DATABASE}.${table_name}" "${clickhouse_url}"; then
                    log_success "Table $table_name truncated"
                else
                    log_error "Failed to truncate table $table_name"
                    return 1
                fi
            else
                log_info "New data will be appended to existing table: $table_name"
            fi
        else
            log_info "Creating new table: $table_name"
            local create_table_sql="
            CREATE TABLE ${CLICKHOUSE_DATABASE}.${table_name} (
                name String,
                version String,
                license String,
                source LowCardinality(String),
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
    jq -r 'to_entries[] | [.key, .value] | @tsv' /app/license-mappings.json > "$mappings_tsv"
    
    # Use awk to apply mappings
    awk -F'\t' '
    BEGIN { OFS="\t" }
    NR==FNR { licenses[$1] = $2; next }
    {
        name = $1; version = $2; license = $3; source = $4;
        if (license == "unknown" || license == "" || license == "null") {
            if (name in licenses) license = licenses[name]
        }
        print name, version, license, source
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

    # Determine source value based on context
    local default_source_value="unknown"
    local sbom_source="${SBOM_SOURCE:-github}"
    local merge_mode="${MERGE:-false}"

    if [[ "$merge_mode" != "true" ]]; then
        # For non-merged SBOMs, determine source from context
        case "$sbom_source" in
            "github")
                default_source_value="${REPOSITORY:-unknown}"
                ;;
            "mend")
                default_source_value="mend:${MEND_PROJECT_UUID:-${MEND_PRODUCT_UUID:-${MEND_ORG_SCOPE_UUID:-unknown}}}"
                ;;
            "wiz")
                default_source_value="wiz:${WIZ_REPORT_ID:-unknown}"
                ;;
            *)
                default_source_value="$sbom_source"
                ;;
        esac
    fi

    log_info "Source value for ClickHouse: $default_source_value"

    # Create temporary file for data
    local data_file="$temp_dir/clickhouse_data.tsv"
    local mapped_data_file="$temp_dir/clickhouse_data_mapped.tsv"
    
    # Extract data based on SBOM format
    case "$sbom_format" in
        "cyclonedx")
            log_debug "Sample CycloneDX component with license:"
            if [[ "${DEBUG:-false}" == "true" ]]; then
                jq -r '.components[0] | {name: .name, version: .version, licenses: .licenses}' "$sbom_file" 2>/dev/null || echo "No components found"
            fi
            # Enhanced extraction to handle component-level source references
            jq -r --arg default_source "$default_source_value" '
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
                    ),
                    (
                        # Use component-level source if available, otherwise use default
                        .source // $default_source
                    )
                ] | @tsv
            ' "$sbom_file" > "$data_file"
            ;;
        "spdxjson")
            # Extract from SPDX format
            # SPDX format doesn't have component-level source in merged SBOMs
            # so always use the default source
            jq -r --arg default_source "$default_source_value" '
                .packages[]? // empty |
                select(.name != null) |
                [
                    .name // "unknown",
                    .versionInfo // "unknown",
                    (.licenseConcluded // .licenseDeclared // "unknown"),
                    (
                        $default_source
                    )
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
    log_info "Found $component_count components to insert (with license mapping and source tracking applied)"
    
    # Insert data into ClickHouse
    if curl -s ${auth_params} \
           -H "Content-Type: text/tab-separated-values" \
           --data-binary "@$mapped_data_file" \
           "${clickhouse_url}/?query=INSERT%20INTO%20${CLICKHOUSE_DATABASE}.${table_name}%20(name,%20version,%20license,%20source)%20FORMAT%20TSV"; then
        log_success "Inserted $component_count components with source tracking into ClickHouse table $table_name"
        return 0
    else
        log_error "Failed to insert data into ClickHouse"
        return 1
    fi
}

# Global variable for temp directory (so cleanup can access it)
temp_dir=""

# Main function
main() {
    log_info "Starting ClickBOM GitHub Action for SBOM processing"

    # Sanitize inputs
    sanitize_inputs
    
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
            local table_name=$(echo "$s3_key" | sed 's|[^a-zA-Z0-9]|_|g' | sed 's|\.json|_merged|g' | tr '[:upper:]' '[:lower:]')
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
