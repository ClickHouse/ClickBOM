// Package sbom provides functionalities for merging multiple SBOMs.
package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ClickHouse/ClickBOM/pkg/logger"
)

// MergedComponent represents a component with source tracking.
type MergedComponent struct {
	Component map[string]interface{}
	Source    string
}

// ExtractSourceReference extracts the source reference from an SBOM file.
func ExtractSourceReference(sbomFile string) (string, error) {
	data, err := os.ReadFile(sbomFile)
	if err != nil {
		return "", fmt.Errorf("failed to read SBOM file: %w", err)
	}

	var sbom map[string]interface{}
	if err := json.Unmarshal(data, &sbom); err != nil {
		return "", fmt.Errorf("failed to parse SBOM: %w", err)
	}

	filename := filepath.Base(sbomFile)
	filename = strings.TrimSuffix(filename, filepath.Ext(filename))

	// Strategy 1: Check for spdx:document:name in properties (GitHub SBOMs)
	if metadata, ok := sbom["metadata"].(map[string]interface{}); ok {
		if properties, ok := metadata["properties"].([]interface{}); ok {
			for _, prop := range properties {
				if propMap, ok := prop.(map[string]interface{}); ok {
					if name, _ := propMap["name"].(string); name == "spdx:document:name" {
						if value, ok := propMap["value"].(string); ok && value != "" {
							logger.Debug("Found SPDX document name: %s", value)
							return value, nil
						}
					}
				}
			}
		}

		// Strategy 2: Check metadata.component.name (Wiz/Mend SBOMs)
		if component, ok := metadata["component"].(map[string]interface{}); ok {
			if name, ok := component["name"].(string); ok && name != "" {
				logger.Debug("Found component name: %s", name)
				return name, nil
			}

			// Strategy 3: Check metadata.component.bom-ref
			if bomRef, ok := component["bom-ref"].(string); ok && bomRef != "" {
				logger.Debug("Found bom-ref: %s", bomRef)
				return bomRef, nil
			}
		}
	}

	// Strategy 4: Check top-level name field
	if name, ok := sbom["name"].(string); ok && name != "" {
		logger.Debug("Found top-level name: %s", name)
		return name, nil
	}

	// Strategy 5: Use filename without extension
	logger.Debug("Using fallback name: %s", filename)
	return filename, nil
}

// CollectComponentsWithSource extracts components from an SBOM and adds source tracking.
func CollectComponentsWithSource(sbomFile, sourceRef string) ([]map[string]interface{}, error) {
	data, err := os.ReadFile(sbomFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM file: %w", err)
	}

	var sbom map[string]interface{}
	if err := json.Unmarshal(data, &sbom); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM: %w", err)
	}

	components, ok := sbom["components"].([]interface{})
	if !ok {
		return []map[string]interface{}{}, nil
	}

	result := make([]map[string]interface{}, 0, len(components))
	for _, comp := range components {
		if compMap, ok := comp.(map[string]interface{}); ok {
			// Add source tracking
			compMap["source"] = sourceRef
			result = append(result, compMap)
		}
	}

	logger.Debug("Collected %d components with source: %s", len(result), sourceRef)
	return result, nil
}

// DeduplicateComponents removes duplicate components based on name+version+purl+source.
func DeduplicateComponents(components []map[string]interface{}) []map[string]interface{} {
	seen := make(map[string]bool)
	unique := make([]map[string]interface{}, 0)

	for _, comp := range components {
		name, _ := comp["name"].(string)
		if name == "" {
			name = "unknown"
		}

		version, _ := comp["version"].(string)
		if version == "" {
			version = "unknown"
		}

		purl, _ := comp["purl"].(string)

		source, _ := comp["source"].(string)
		if source == "" {
			source = "unknown"
		}

		// Create unique key
		key := fmt.Sprintf("%s@%s#%s^%s", name, version, purl, source)

		if !seen[key] {
			seen[key] = true
			unique = append(unique, comp)
		}
	}

	logger.Info("Deduplicated %d components down to %d unique components", len(components), len(unique))
	return unique
}

// MergeSBOMs merges multiple CycloneDX SBOMs into one with source tracking.
func MergeSBOMs(inputFiles []string, outputFile string) error {
	logger.Info("Merging %d CycloneDX SBOMs with source tracking", len(inputFiles))

	if len(inputFiles) == 0 {
		return fmt.Errorf("no input files provided")
	}

	// Create merged SBOM metadata
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	serialNumber := fmt.Sprintf("urn:uuid:%s", uuid.New().String())

	mergedSBOM := map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"serialNumber": serialNumber,
		"version":      1,
		"metadata": map[string]interface{}{
			"timestamp": timestamp,
			"tools": []map[string]interface{}{
				{
					"vendor":  "ClickBOM",
					"name":    "cyclonedx-merge",
					"version": "2.0.0",
				},
			},
			"component": map[string]interface{}{
				"type":    "application",
				"name":    "merged-sbom",
				"version": "1.0.0",
			},
		},
		"components": []map[string]interface{}{},
	}

	// Collect all components with source tracking
	allComponents := make([]map[string]interface{}, 0)

	for _, sbomFile := range inputFiles {
		sourceRef, err := ExtractSourceReference(sbomFile)
		if err != nil {
			logger.Warning("Failed to extract source reference from %s: %v", filepath.Base(sbomFile), err)
			sourceRef = filepath.Base(sbomFile)
		}

		components, err := CollectComponentsWithSource(sbomFile, sourceRef)
		if err != nil {
			logger.Warning("Failed to collect components from %s: %v", filepath.Base(sbomFile), err)
			continue
		}

		logger.Info("Processing %s: %d components (source: %s)",
			filepath.Base(sbomFile), len(components), sourceRef)

		allComponents = append(allComponents, components...)
	}

	// Deduplicate components
	uniqueComponents := DeduplicateComponents(allComponents)
	mergedSBOM["components"] = uniqueComponents

	// Write merged SBOM to file
	data, err := json.MarshalIndent(mergedSBOM, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal merged SBOM: %w", err)
	}

	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write merged SBOM: %w", err)
	}

	logger.Success("Successfully merged %d SBOMs into one with %d unique components",
		len(inputFiles), len(uniqueComponents))

	// Log summary
	logger.Info("Merge summary with source tracking:")
	for _, sbomFile := range inputFiles {
		sourceRef, _ := ExtractSourceReference(sbomFile)
		data, _ := os.ReadFile(sbomFile)
		var sbom map[string]interface{}
		err := json.Unmarshal(data, &sbom)
		if err != nil {
			continue
		}
		compCount := 0
		if components, ok := sbom["components"].([]interface{}); ok {
			compCount = len(components)
		}
		logger.Info("  - %s: %d components (source: %s)",
			strings.TrimSuffix(filepath.Base(sbomFile), ".json"), compCount, sourceRef)
	}

	return nil
}
