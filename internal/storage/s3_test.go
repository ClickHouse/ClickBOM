//go:build integration
// +build integration

package integration

import (
	"context"
	"os"
	"testing"

	"github.com/ClickHouse/ClickBOM/internal/storage"
)

func TestS3Upload(t *testing.T) {
	// Skip if not in integration test mode
	if os.Getenv("AWS_ENDPOINT_URL") == "" {
		t.Skip("Skipping integration test - AWS_ENDPOINT_URL not set")
	}

	ctx := context.Background()

	// Create S3 client
	s3Client, err := storage.NewS3Client(
		ctx,
		"test",
		"test",
		"us-east-1",
	)
	if err != nil {
		t.Fatalf("Failed to create S3 client: %v", err)
	}

	// Create test file
	testFile := "/tmp/test-sbom.json"
	testContent := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(testFile)

	// Upload
	bucket := "test-bucket"
	key := "test.json"

	err = s3Client.Upload(ctx, testFile, bucket, key, "cyclonedx")
	if err != nil {
		t.Fatalf("Failed to upload: %v", err)
	}

	// Download and verify
	downloadFile := "/tmp/downloaded-sbom.json"
	defer os.Remove(downloadFile)

	err = s3Client.Download(ctx, bucket, key, downloadFile)
	if err != nil {
		t.Fatalf("Failed to download: %v", err)
	}

	// Verify content
	downloaded, err := os.ReadFile(downloadFile)
	if err != nil {
		t.Fatalf("Failed to read downloaded file: %v", err)
	}

	if string(downloaded) != string(testContent) {
		t.Errorf("Downloaded content doesn't match. Got %s, want %s", downloaded, testContent)
	}
}
