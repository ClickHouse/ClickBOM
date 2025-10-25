#!/bin/bash
# SBOM merging functionality

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

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
            "version": "1.0.10"
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

    local i=0

    # Collect all components with source information
    for i in "${!cyclonedx_files[@]}"; do
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
            "version": "1.0.10"
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
