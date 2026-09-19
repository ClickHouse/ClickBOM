//go:build integration

package sbom

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestGitHubDownloadSBOMLive exercises the asynchronous SBOM export against
// the real GitHub API. It needs GITHUB_TOKEN (CI passes the workflow token)
// and targets this repository unless GITHUB_SBOM_TEST_REPOSITORY overrides it.
func TestGitHubDownloadSBOMLive(t *testing.T) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		t.Skip("GITHUB_TOKEN not set")
	}
	repo := os.Getenv("GITHUB_SBOM_TEST_REPOSITORY")
	if repo == "" {
		repo = "ClickHouse/ClickBOM"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	out := filepath.Join(t.TempDir(), "sbom.json")
	if err := NewGitHubClient(token).DownloadSBOM(ctx, repo, out); err != nil {
		t.Fatalf("DownloadSBOM(%s): %v", repo, err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SPDXVersion string            `json:"spdxVersion"`
		Packages    []json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("downloaded SBOM is not valid JSON: %v", err)
	}
	if !strings.HasPrefix(doc.SPDXVersion, "SPDX-") {
		t.Errorf("spdxVersion = %q, want an SPDX document", doc.SPDXVersion)
	}
	if len(doc.Packages) == 0 {
		t.Error("downloaded SBOM has no packages")
	}

	// The asynchronous API returns the document unwrapped; make sure the rest
	// of the pipeline still recognises it.
	extracted := filepath.Join(t.TempDir(), "extracted.json")
	if err := ExtractSBOMFromWrapper(out, extracted); err != nil {
		t.Fatalf("ExtractSBOMFromWrapper: %v", err)
	}
	format, err := DetectSBOMFormat(extracted)
	if err != nil {
		t.Fatalf("DetectSBOMFormat: %v", err)
	}
	if format != FormatSPDXJSON {
		t.Errorf("DetectSBOMFormat = %s, want %s", format, FormatSPDXJSON)
	}
	t.Logf("%s: %d bytes, %d packages, %s", repo, len(data), len(doc.Packages), doc.SPDXVersion)
}
