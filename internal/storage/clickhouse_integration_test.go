//go:build integration

package storage

import (
	"context"
	"os"
	"testing"

	"github.com/ClickHouse/ClickBOM/internal/config"
)

func TestClickHouseIntegration(t *testing.T) {
	if os.Getenv("CLICKHOUSE_URL") == "" {
		t.Skip("Skipping integration test - CLICKHOUSE_URL not set")
	}

	ctx := context.Background()

	// Create ClickHouse client
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

	tableName := "test_sbom_components"

	t.Run("Setup ClickHouse table", func(t *testing.T) {
		err := chClient.SetupTable(ctx, tableName)
		if err != nil {
			t.Fatalf("Failed to setup table: %v", err)
		}

		t.Logf("✓ Successfully set up table: %s", tableName)
	})

	t.Run("Insert SBOM data", func(t *testing.T) {
		// Create test SBOM file
		testSBOM := `/tmp/test-clickhouse-sbom.json`
		testContent := `{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "name": "lodash",
                    "version": "4.17.21",
                    "type": "library",
                    "licenses": [
                        {
                            "license": {
                                "id": "MIT"
                            }
                        }
                    ],
                    "source": "github"
                },
                {
                    "name": "react",
                    "version": "18.2.0",
                    "type": "library",
                    "licenses": [
                        {
                            "license": {
                                "id": "MIT"
                            }
                        }
                    ],
                    "source": "github"
                }
            ]
        }`

		if err := os.WriteFile(testSBOM, []byte(testContent), 0644); err != nil {
			t.Fatalf("Failed to create test SBOM: %v", err)
		}
		defer os.Remove(testSBOM)

		// Insert data
		err := chClient.InsertSBOMData(ctx, testSBOM, tableName, "cyclonedx")
		if err != nil {
			t.Fatalf("Failed to insert data: %v", err)
		}

		t.Log("✓ Successfully inserted SBOM data into ClickHouse")
	})

	t.Run("Verify table migration", func(t *testing.T) {
		// This tests the source column migration
		err := chClient.SetupTable(ctx, tableName)
		if err != nil {
			t.Fatalf("Failed during table setup/migration: %v", err)
		}

		t.Log("✓ Table migration check passed")
	})
}
