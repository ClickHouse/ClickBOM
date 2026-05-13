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

	// Fallback: parse as a generic object and probe for marker fields that the
	// strict-typed structs above can miss (CycloneDX without bomFormat but with
	// metadata.component, SPDX without spdxVersion but with SPDXID).
	var generic map[string]interface{}
	if err := json.Unmarshal(data, &generic); err == nil {
		if metadata, ok := generic["metadata"].(map[string]interface{}); ok {
			if _, ok := metadata["component"].(map[string]interface{}); ok {
				logger.Debug("Detected format: CycloneDX (via metadata.component)")
				return FormatCycloneDX, nil
			}
		}
		if id, ok := generic["SPDXID"].(string); ok && id != "" {
			logger.Debug("Detected format: SPDX (via SPDXID)")
			return FormatSPDXJSON, nil
		}
	}

	logger.Warning("Unknown SBOM format")
	return FormatUnknown, nil
}

// FixSPDXCompatibility normalizes SPDX referenceCategory values that the
// cyclonedx-cli convert command rejects. Walks the JSON tree and rewrites
// every object's referenceCategory to one of the SPDX 2.2 spec values:
// SECURITY, PACKAGE_MANAGER, PERSISTENT_ID, OTHER. The common offender is
// "PACKAGE-MANAGER" (with a hyphen), which must become "PACKAGE_MANAGER".
func FixSPDXCompatibility(inputFile, outputFile string) error {
	logger.Info("Fixing SPDX compatibility issues for CycloneDX conversion")

	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var doc interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	normalizeReferenceCategories(doc)

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SBOM: %w", err)
	}

	if err := os.WriteFile(outputFile, out, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	logger.Success("SPDX compatibility fixes applied")
	return nil
}

func normalizeReferenceCategories(node interface{}) {
	switch v := node.(type) {
	case map[string]interface{}:
		if cat, ok := v["referenceCategory"].(string); ok {
			switch cat {
			case "PACKAGE-MANAGER":
				v["referenceCategory"] = "PACKAGE_MANAGER"
			case "SECURITY", "PACKAGE_MANAGER", "PERSISTENT_ID", "OTHER":
				// Already valid, leave as-is.
			default:
				v["referenceCategory"] = "OTHER"
			}
		}
		for _, child := range v {
			normalizeReferenceCategories(child)
		}
	case []interface{}:
		for _, child := range v {
			normalizeReferenceCategories(child)
		}
	}
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

	// cyclonedx-cli's --input-format spells CycloneDX JSON as "json", not
	// "cyclonedx". Map our internal Format names to the CLI's expected values.
	cliInputFormat := string(sourceFormat)
	if sourceFormat == FormatCycloneDX {
		cliInputFormat = "json"
	}

	args := []string{
		"convert",
		"--input-file", inputFile,
		"--output-file", outputFile,
		"--input-format", cliInputFormat,
		"--output-format", string(targetFormat),
	}
	// Pin CycloneDX output to v1.6 (parity with bash and with MergeSBOMs which
	// always emits specVersion 1.6); otherwise cyclonedx-cli defaults to 1.4.
	if targetFormat == FormatCycloneDX {
		args = append(args, "--output-version", "v1_6")
	}

	output, err := exec.Command("cyclonedx", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("conversion failed: %w\nOutput: %s", err, string(output))
	}

	logger.Success("SBOM converted successfully")
	return nil
}
