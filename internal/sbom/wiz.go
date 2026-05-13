// Package sbom provides functionalities to interact with Software Bill of Materials (SBOM).
package sbom

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ClickHouse/ClickBOM/internal/config"
	"github.com/ClickHouse/ClickBOM/pkg/logger"
)

// WizClient handles interactions with the Wiz API.
type WizClient struct {
	authEndpoint string
	apiEndpoint  string
	clientID     string
	clientSecret string
	reportID     string
	httpClient   *http.Client
	accessToken  string
}

// NewWizClient creates a new WizClient with the provided configuration.
func NewWizClient(cfg *config.Config) *WizClient {
	return &WizClient{
		authEndpoint: cfg.WizAuthEndpoint,
		apiEndpoint:  cfg.WizAPIEndpoint,
		clientID:     cfg.WizClientID,
		clientSecret: cfg.WizClientSecret,
		reportID:     cfg.WizReportID,
		httpClient: &http.Client{
			Timeout: 10 * time.Minute,
		},
	}
}

func (w *WizClient) authenticate(ctx context.Context) error {
	logger.Info("Authenticating with Wiz API")

	// OAuth 2.0 RFC 6749 client_credentials grants are form-encoded, not JSON.
	// Wiz's auth endpoint enforces this; sending JSON yields a generic 401.
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", w.clientID)
	form.Set("client_secret", w.clientSecret)
	form.Set("audience", "wiz-api")

	req, err := http.NewRequestWithContext(ctx, "POST", w.authEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("authentication request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warning("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed (status %d): %s", resp.StatusCode, string(body))
	}

	var authResp struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to parse auth response: %w", err)
	}

	if authResp.AccessToken == "" {
		return fmt.Errorf("no access token in response")
	}

	w.accessToken = authResp.AccessToken
	logger.Success("Wiz authentication successful")
	return nil
}

// DownloadReport downloads the Wiz report and saves it to the specified output file.
func (w *WizClient) DownloadReport(ctx context.Context, outputFile string) error {
	logger.Info("Downloading Wiz report: %s", w.reportID)

	// Authenticate first
	if err := w.authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// GraphQL query to get download URL
	query := fmt.Sprintf(`{
        "query": "query ReportDownloadUrl($reportId: ID!) { report(id: $reportId) { lastRun { url } } }",
        "variables": {
            "reportId": "%s"
        }
    }`, w.reportID)

	req, err := http.NewRequestWithContext(ctx, "POST",
		w.apiEndpoint+"/api/graphql",
		bytes.NewReader([]byte(query)))
	if err != nil {
		return fmt.Errorf("failed to create GraphQL request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+w.accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GraphQL request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warning("Failed to close response body: %v", err)
		}
	}()

	var graphqlResp struct {
		Data struct {
			Report struct {
				LastRun struct {
					URL string `json:"url"`
				} `json:"lastRun"`
			} `json:"report"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&graphqlResp); err != nil {
		return fmt.Errorf("failed to parse GraphQL response: %w", err)
	}

	if len(graphqlResp.Errors) > 0 {
		return fmt.Errorf("a Wiz GraphQL error has occurred: %s", graphqlResp.Errors[0].Message)
	}

	downloadURL := graphqlResp.Data.Report.LastRun.URL
	if downloadURL == "" {
		return fmt.Errorf("no download URL found in response")
	}

	logger.Info("Got download URL from Wiz")

	// Download the report
	return w.downloadFromURL(ctx, downloadURL, outputFile)
}

func (w *WizClient) downloadFromURL(ctx context.Context, url, outputFile string) error {
	logger.Info("Downloading Wiz report from URL")

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create download request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+w.accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warning("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download failed (status %d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	jsonBytes, err := normalizeWizPayload(body, filepath.Dir(outputFile))
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputFile, jsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	logger.Success("Wiz report downloaded successfully (%d bytes)", len(jsonBytes))

	if err := validateJSON(outputFile); err != nil {
		return fmt.Errorf("downloaded file is not valid JSON: %w", err)
	}
	return nil
}

// normalizeWizPayload turns whatever Wiz's signed-URL endpoint returned (raw
// JSON, gzip-compressed JSON, or a ZIP archive that may contain one or many
// CycloneDX SBOM JSON files) into a single JSON byte buffer ready to be
// written to disk. workDir is used as a scratch directory when ZIP entries
// must be staged for a local merge.
func normalizeWizPayload(body []byte, workDir string) ([]byte, error) {
	switch {
	case hasGzipMagic(body):
		logger.Info("Wiz response is gzip-compressed, decompressing")
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("failed to open gzip stream: %w", err)
		}
		defer func() { _ = gz.Close() }()
		return io.ReadAll(gz)

	case hasZipMagic(body):
		logger.Info("Wiz response is a ZIP archive, extracting")
		return extractJSONFromWizZip(body, workDir)

	default:
		return body, nil
	}
}

// hasGzipMagic reports whether the buffer starts with the gzip magic bytes.
func hasGzipMagic(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1F && b[1] == 0x8B
}

// extractJSONFromWizZip walks a Wiz signed-URL ZIP. If it contains a single
// JSON file the contents are returned directly; if it contains multiple, they
// are staged to workDir and merged locally with MergeSBOMs so callers get a
// single CycloneDX-shaped document either way.
func extractJSONFromWizZip(body []byte, workDir string) ([]byte, error) {
	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to read ZIP: %w", err)
	}

	var stagedPaths []string
	for _, file := range zipReader.File {
		if file.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(file.Name), ".json") {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open %s in ZIP: %w", file.Name, err)
		}
		contents, readErr := io.ReadAll(rc)
		_ = rc.Close()
		if readErr != nil {
			return nil, fmt.Errorf("failed to read %s in ZIP: %w", file.Name, readErr)
		}
		// Stage to disk so MergeSBOMs can read it back.
		safeName := filepath.Base(file.Name)
		staged := filepath.Join(workDir, "wiz_zip_"+safeName)
		if err := os.WriteFile(staged, contents, 0644); err != nil {
			return nil, fmt.Errorf("failed to stage %s: %w", file.Name, err)
		}
		stagedPaths = append(stagedPaths, staged)
	}

	switch len(stagedPaths) {
	case 0:
		return nil, fmt.Errorf("Wiz ZIP contains no .json entries")
	case 1:
		return os.ReadFile(stagedPaths[0])
	}

	logger.Info("Wiz ZIP contains %d JSON files, merging locally", len(stagedPaths))
	mergedPath := filepath.Join(workDir, "wiz_zip_merged.json")
	if err := MergeSBOMs(stagedPaths, mergedPath); err != nil {
		return nil, fmt.Errorf("failed to merge ZIP entries: %w", err)
	}
	return os.ReadFile(mergedPath)
}
