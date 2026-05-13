package storage

import (
	"context"
	"os"
	"testing"
)

func TestLocalFilenameForKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{name: "flat key untouched", key: "sbom.json", want: "sbom.json"},
		{name: "one level of prefix", key: "teamA/sbom.json", want: "teamA_sbom.json"},
		{name: "deeper prefix", key: "prod/2026/Q1/sbom.json", want: "prod_2026_Q1_sbom.json"},
		{name: "leading slash trimmed", key: "/teamA/sbom.json", want: "teamA_sbom.json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := localFilenameForKey(tc.key); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("collision-resistance", func(t *testing.T) {
		a := localFilenameForKey("teamA/sbom.json")
		b := localFilenameForKey("teamB/sbom.json")
		if a == b {
			t.Errorf("sibling keys produced same local name: %q", a)
		}
	})
}

func TestS3Upload(t *testing.T) {
	// Skip if not in integration test mode
	if os.Getenv("AWS_ENDPOINT_URL") == "" {
		t.Skip("Skipping integration test - AWS_ENDPOINT_URL not set")
	}

	ctx := context.Background()

	// Create S3 client
	s3Client, err := NewS3Client(ctx)
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
