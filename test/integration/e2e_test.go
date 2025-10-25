//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ClickHouse/ClickBOM/internal/config"
	"github.com/ClickHouse/ClickBOM/internal/sbom"
	"github.com/ClickHouse/ClickBOM/internal/storage"
)

func TestEndToEndWorkflow(t *testing.T) {
	if os.Getenv("AWS_ENDPOINT_URL") == "" || os.Getenv("CLICKHOUSE_URL") == "" {
		t.Skip("Skipping E2E test - AWS_ENDPOINT_URL or CLICKHOUSE_URL not set")
	}

	ctx := context.Background()

	// Create temp directory for test files
	tempDir := t.TempDir()

	t.Run("Complete SBOM workflow", func(t *testing.T) {
		// Step 1: Create a mock SBOM
		originalSBOM := filepath.Join(tempDir, "original.json")
		sbomContent := `{
            "sbom": {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "test-document",
                "packages": [
                    {
                        "name": "test-package",
                        "versionInfo": "1.0.0",
                        "licenseConcluded": "MIT"
                    }
                ]
            }
        }`

		if err := os.WriteFile(originalSBOM, []byte(sbomContent), 0644); err != nil {
			t.Fatalf("Failed to create test SBOM: %v", err)
		}

		t.Log("✓ Created test SBOM file")

		// Step 2: Extract from wrapper
		extractedSBOM := filepath.Join(tempDir, "extracted.json")
		if err := sbom.ExtractSBOMFromWrapper(originalSBOM, extractedSBOM); err != nil {
			t.Fatalf("Failed to extract SBOM: %v", err)
		}

		t.Log("✓ Extracted SBOM from wrapper")

		// Step 3: Detect format
		format, err := sbom.DetectSBOMFormat(extractedSBOM)
		if err != nil {
			t.Fatalf("Failed to detect format: %v", err)
		}

		if format != sbom.FormatSPDXJSON {
			t.Errorf("Expected SPDX format, got %s", format)
		}

		t.Logf("✓ Detected format: %s", format)

		// Step 4: Convert to CycloneDX
		convertedSBOM := filepath.Join(tempDir, "converted.json")
		if err := sbom.ConvertSBOM(extractedSBOM, convertedSBOM, format, sbom.FormatCycloneDX); err != nil {
			t.Fatalf("Failed to convert SBOM: %v", err)
		}

		t.Log("✓ Converted SBOM to CycloneDX")

		// Step 5: Upload to S3
		s3Client, err := storage.NewS3Client(
			ctx,
			os.Getenv("AWS_ACCESS_KEY_ID"),
			os.Getenv("AWS_SECRET_ACCESS_KEY"),
			os.Getenv("AWS_DEFAULT_REGION"),
		)
		if err != nil {
			t.Fatalf("Failed to create S3 client: %v", err)
		}

		testBucket := "test-bucket"
		testKey := "e2e-test.json"

		if err := s3Client.Upload(ctx, convertedSBOM, testBucket, testKey, "cyclonedx"); err != nil {
			t.Fatalf("Failed to upload to S3: %v", err)
		}

		t.Log("✓ Uploaded SBOM to S3")

		// Step 6: Insert into ClickHouse
		cfg := &config.Config{
			ClickHouseURL:      os.Getenv("CLICKHOUSE_URL"),
			ClickHouseDatabase: "default",
			ClickHouseUsername: "default",
			ClickHousePassword: "",
			TruncateTable:      true,
		}

		chClient, err := storage.NewClickHouseClient(cfg)
		if err != nil {
			t.Fatalf("Failed to create ClickHouse client: %v", err)
		}

		tableName := "e2e_test_sbom"

		if err := chClient.SetupTable(ctx, tableName); err != nil {
			t.Fatalf("Failed to setup ClickHouse table: %v", err)
		}

		if err := chClient.InsertSBOMData(ctx, convertedSBOM, tableName, "cyclonedx"); err != nil {
			t.Fatalf("Failed to insert into ClickHouse: %v", err)
		}

		t.Log("✓ Inserted data into ClickHouse")

		// Step 7: Download from S3 and verify
		downloadedSBOM := filepath.Join(tempDir, "downloaded.json")
		if err := s3Client.Download(ctx, testBucket, testKey, downloadedSBOM); err != nil {
			t.Fatalf("Failed to download from S3: %v", err)
		}

		// Verify downloaded file exists and has content
		downloadedData, err := os.ReadFile(downloadedSBOM)
		if err != nil {
			t.Fatalf("Failed to read downloaded file: %v", err)
		}

		if len(downloadedData) == 0 {
			t.Error("Downloaded file is empty")
		}

		t.Log("✓ Downloaded and verified SBOM from S3")
	})
}
