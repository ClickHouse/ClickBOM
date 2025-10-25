//go:build integration

package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClickHouse/ClickBOM/internal/sbom"
)

func TestSBOMProcessing(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("Extract SBOM from GitHub wrapper", func(t *testing.T) {
		wrappedSBOM := filepath.Join(tempDir, "wrapped.json")
		wrappedContent := `{
            "sbom": {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": []
            }
        }`

		if err := os.WriteFile(wrappedSBOM, []byte(wrappedContent), 0644); err != nil {
			t.Fatalf("Failed to create wrapped SBOM: %v", err)
		}

		extractedSBOM := filepath.Join(tempDir, "extracted.json")
		if err := sbom.ExtractSBOMFromWrapper(wrappedSBOM, extractedSBOM); err != nil {
			t.Fatalf("Failed to extract: %v", err)
		}

		// Verify extracted file
		data, err := os.ReadFile(extractedSBOM)
		if err != nil {
			t.Fatalf("Failed to read extracted file: %v", err)
		}

		if len(data) == 0 {
			t.Error("Extracted file is empty")
		}

		t.Log("✓ Successfully extracted SBOM from wrapper")
	})

	t.Run("Detect CycloneDX format", func(t *testing.T) {
		cdxSBOM := filepath.Join(tempDir, "cyclonedx.json")
		cdxContent := `{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": []
        }`

		if err := os.WriteFile(cdxSBOM, []byte(cdxContent), 0644); err != nil {
			t.Fatalf("Failed to create CycloneDX SBOM: %v", err)
		}

		format, err := sbom.DetectSBOMFormat(cdxSBOM)
		if err != nil {
			t.Fatalf("Failed to detect format: %v", err)
		}

		if format != sbom.FormatCycloneDX {
			t.Errorf("Expected CycloneDX, got %s", format)
		}

		t.Log("✓ Correctly detected CycloneDX format")
	})

	t.Run("Detect SPDX format", func(t *testing.T) {
		spdxSBOM := filepath.Join(tempDir, "spdx.json")
		spdxContent := `{
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test"
        }`

		if err := os.WriteFile(spdxSBOM, []byte(spdxContent), 0644); err != nil {
			t.Fatalf("Failed to create SPDX SBOM: %v", err)
		}

		format, err := sbom.DetectSBOMFormat(spdxSBOM)
		if err != nil {
			t.Fatalf("Failed to detect format: %v", err)
		}

		if format != sbom.FormatSPDXJSON {
			t.Errorf("Expected SPDX, got %s", format)
		}

		t.Log("✓ Correctly detected SPDX format")
	})

	t.Run("Convert same format (copy)", func(t *testing.T) {
		inputSBOM := filepath.Join(tempDir, "input.json")
		outputSBOM := filepath.Join(tempDir, "output.json")

		content := `{"bomFormat":"CycloneDX","specVersion":"1.6"}`
		if err := os.WriteFile(inputSBOM, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create input SBOM: %v", err)
		}

		err := sbom.ConvertSBOM(inputSBOM, outputSBOM, sbom.FormatCycloneDX, sbom.FormatCycloneDX)
		if err != nil {
			t.Fatalf("Failed to convert: %v", err)
		}

		// Verify output exists
		if _, err := os.Stat(outputSBOM); os.IsNotExist(err) {
			t.Error("Output file was not created")
		}

		t.Log("✓ Same format conversion (copy) successful")
	})
}
