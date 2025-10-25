//go:build integration

package storage

import (
	"context"
	"os"
	"testing"
)

func TestS3Integration(t *testing.T) {
	// Skip if not in integration test mode
	if os.Getenv("AWS_ENDPOINT_URL") == "" {
		t.Skip("Skipping integration test - AWS_ENDPOINT_URL not set")
	}

	ctx := context.Background()

	// Create S3 client
	s3Client, err := storage.NewS3Client(
		ctx,
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		os.Getenv("AWS_DEFAULT_REGION"),
	)
	if err != nil {
		t.Fatalf("Failed to create S3 client: %v", err)
	}

	// Test data
	testBucket := "test-bucket"
	testKey := "test-sbom.json"
	testContent := `{
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test-123",
        "version": 1,
        "components": [
            {
                "name": "test-component",
                "version": "1.0.0",
                "type": "library"
            }
        ]
    }`

	t.Run("Upload SBOM to S3", func(t *testing.T) {
		// Create test file
		testFile := "/tmp/test-sbom.json"
		if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
		defer os.Remove(testFile)

		// Upload
		err := s3Client.Upload(ctx, testFile, testBucket, testKey, "cyclonedx")
		if err != nil {
			t.Fatalf("Failed to upload: %v", err)
		}

		t.Log("✓ Successfully uploaded SBOM to S3")
	})

	t.Run("Download SBOM from S3", func(t *testing.T) {
		downloadFile := "/tmp/downloaded-sbom.json"
		defer os.Remove(downloadFile)

		err := s3Client.Download(ctx, testBucket, testKey, downloadFile)
		if err != nil {
			t.Fatalf("Failed to download: %v", err)
		}

		// Verify content
		downloaded, err := os.ReadFile(downloadFile)
		if err != nil {
			t.Fatalf("Failed to read downloaded file: %v", err)
		}

		if len(downloaded) == 0 {
			t.Error("Downloaded file is empty")
		}

		t.Logf("✓ Successfully downloaded SBOM from S3 (%d bytes)", len(downloaded))
	})

	t.Run("List S3 objects", func(t *testing.T) {
		keys, err := s3Client.ListObjects(ctx, testBucket, "")
		if err != nil {
			t.Fatalf("Failed to list objects: %v", err)
		}

		if len(keys) == 0 {
			t.Error("No objects found in bucket")
		}

		// Verify our test file is in the list
		found := false
		for _, key := range keys {
			if key == testKey {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Test file %s not found in bucket listing", testKey)
		}

		t.Logf("✓ Found %d objects in S3 bucket", len(keys))
	})
}
