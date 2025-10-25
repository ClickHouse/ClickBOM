// Package sbom provides functionalities to interact with Software Bill of Materials (SBOM).
package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/ClickHouse/ClickBOM/pkg/logger"
)

// Format represents the format of a Software Bill of Materials (SBOM).
type Format string

const (
	// FormatCycloneDX represents the CycloneDX SBOM format.
	FormatCycloneDX Format = "cyclonedx"
	// FormatSPDXJSON represents the SPDX JSON SBOM format.
	FormatSPDXJSON Format = "spdxjson"
	// FormatUnknown represents an unknown SBOM format.
	FormatUnknown Format = "unknown"
)

// CycloneDXDocument represents the basic structure of a CycloneDX SBOM.
type CycloneDXDocument struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
}

// SPDXDocument represents the basic structure of an SPDX SBOM.
type SPDXDocument struct {
	SPDXVersion string `json:"spdxVersion"`
	SPDXID      string `json:"SPDXID"`
}

// DetectSBOMFormat detects the format of the SBOM file based on its content.
func DetectSBOMFormat(filename string) (Format, error) {
	logger.Debug("Detecting SBOM format for: %s", filename)

	data, err := os.ReadFile(filename)
	if err != nil {
		return FormatUnknown, fmt.Errorf("failed to read file: %w", err)
	}

	// Try CycloneDX
	var cdx CycloneDXDocument
	if err := json.Unmarshal(data, &cdx); err == nil {
		if cdx.BOMFormat == "CycloneDX" {
			logger.Debug("Detected format: CycloneDX")
			return FormatCycloneDX, nil
		}
	}

	// Try SPDX
	var spdx SPDXDocument
	if err := json.Unmarshal(data, &spdx); err == nil {
		if spdx.SPDXVersion != "" {
			logger.Debug("Detected format: SPDX")
			return FormatSPDXJSON, nil
		}
	}

	logger.Warning("Unknown SBOM format")
	return FormatUnknown, nil
}

// ExtractSBOMFromWrapper extracts the SBOM from a wrapper format (e.g., GitHub) if necessary.
func ExtractSBOMFromWrapper(inputFile, outputFile string) error {
	logger.Debug("Checking if SBOM is wrapped")

	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var wrapper map[string]interface{}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Check if there's an 'sbom' field (GitHub wrapper)
	if sbomData, ok := wrapper["sbom"]; ok {
		logger.Info("Found wrapped SBOM, extracting...")

		sbomJSON, err := json.MarshalIndent(sbomData, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal SBOM: %w", err)
		}

		if err := os.WriteFile(outputFile, sbomJSON, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}

		logger.Success("SBOM extracted from wrapper")
		return nil
	}

	// Not wrapped, just copy
	logger.Debug("SBOM is not wrapped")
	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

// ConvertSBOM converts the SBOM from one format to another.
func ConvertSBOM(inputFile, outputFile string, sourceFormat, targetFormat Format) error {
	if sourceFormat == targetFormat {
		logger.Info("Source and target formats are the same, copying file")
		data, err := os.ReadFile(inputFile)
		if err != nil {
			return err
		}
		return os.WriteFile(outputFile, data, 0644)
	}

	logger.Info("Converting SBOM from %s to %s", sourceFormat, targetFormat)

	// Use cyclonedx-cli for conversion
	cmd := exec.Command("cyclonedx",
		"convert",
		"--input-file", inputFile,
		"--output-file", outputFile,
		"--input-format", string(sourceFormat),
		"--output-format", string(targetFormat),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("conversion failed: %w\nOutput: %s", err, string(output))
	}

	logger.Success("SBOM converted successfully")
	return nil
}
