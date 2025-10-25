// Package sbom provides functionalities to interact with Software Bill of Materials (SBOM).
package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

	data := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     w.clientID,
		"client_secret": w.clientSecret,
		"audience":      "wiz-api",
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal auth data: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", w.authEndpoint, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
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

	// Create output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		if err := outFile.Close(); err != nil {
			logger.Warning("Failed to close file: %v", err)
		}
	}()

	// Copy response to file
	written, err := io.Copy(outFile, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	logger.Success("Wiz report downloaded successfully (%d bytes)", written)

	// Validate JSON
	if err := validateJSON(outputFile); err != nil {
		return fmt.Errorf("downloaded file is not valid JSON: %w", err)
	}

	return nil
}
