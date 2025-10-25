// Package sbom provides functionalities to interact with Mend API 3.0 for SBOM export.
package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ClickHouse/ClickBOM/internal/config"
	"github.com/ClickHouse/ClickBOM/pkg/logger"
)

// MendClient handles interactions with the Mend API 3.0.
type MendClient struct {
	email        string
	orgUUID      string
	userKey      string
	baseURL      string
	projectUUID  string
	productUUID  string
	orgScopeUUID string
	projectUUIDs string
	maxWaitTime  int
	pollInterval int
	httpClient   *http.Client
	jwtToken     string
}

// NewMendClient creates a new MendClient with the provided configuration.
func NewMendClient(cfg *config.Config) *MendClient {
	return &MendClient{
		email:        cfg.MendEmail,
		orgUUID:      cfg.MendOrgUUID,
		userKey:      cfg.MendUserKey,
		baseURL:      cfg.MendBaseURL,
		projectUUID:  cfg.MendProjectUUID,
		productUUID:  cfg.MendProductUUID,
		orgScopeUUID: cfg.MendOrgScopeUUID,
		projectUUIDs: cfg.MendProjectUUIDs,
		maxWaitTime:  cfg.MendMaxWaitTime,
		pollInterval: cfg.MendPollInterval,
		httpClient: &http.Client{
			Timeout: 10 * time.Minute,
		},
	}
}

func (m *MendClient) authenticate(ctx context.Context) error {
	logger.Info("Authenticating with Mend API 3.0")

	loginPayload := map[string]string{
		"email":   m.email,
		"orgUuid": m.orgUUID,
		"userKey": m.userKey,
	}

	payloadBytes, err := json.Marshal(loginPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal login payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		m.baseURL+"/api/v3.0/login",
		bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
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

	var loginResp struct {
		Response struct {
			RefreshToken string `json:"refreshToken"`
			JWTToken     string `json:"jwtToken"`
		} `json:"response"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return fmt.Errorf("failed to parse login response: %w", err)
	}

	// Try to get JWT directly from login response
	if loginResp.Response.JWTToken != "" {
		m.jwtToken = loginResp.Response.JWTToken
		logger.Success("Mend authentication successful")
		return nil
	}

	// Otherwise use refresh token to get JWT
	if loginResp.Response.RefreshToken == "" {
		return fmt.Errorf("no refresh token or JWT token in response")
	}

	// Get JWT token using refresh token
	req, err = http.NewRequestWithContext(ctx, "POST",
		m.baseURL+"/api/v3.0/login/accessToken",
		nil)
	if err != nil {
		return fmt.Errorf("failed to create JWT request: %w", err)
	}

	req.Header.Set("wss-refresh-token", loginResp.Response.RefreshToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err = m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get JWT token: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warning("Failed to close response body: %v", err)
		}
	}()

	var jwtResp struct {
		Response struct {
			JWTToken string `json:"jwtToken"`
		} `json:"response"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwtResp); err != nil {
		return fmt.Errorf("failed to parse JWT response: %w", err)
	}

	if jwtResp.Response.JWTToken == "" {
		return fmt.Errorf("no JWT token in response")
	}

	m.jwtToken = jwtResp.Response.JWTToken
	logger.Success("Mend authentication successful")
	return nil
}

// RequestSBOMExport requests an SBOM export and downloads it when ready.
func (m *MendClient) RequestSBOMExport(ctx context.Context, outputFile string) error {
	logger.Info("Requesting SBOM export from Mend API 3.0")

	// Authenticate first
	if err := m.authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Build request payload
	payload := map[string]interface{}{
		"name":                   "clickbom-export",
		"reportType":             "cycloneDX_1_5",
		"format":                 "json",
		"includeVulnerabilities": false,
	}

	// Add scope
	switch {
	case m.projectUUID != "":
		payload["scopeType"] = "project"
		payload["scopeUuid"] = m.projectUUID
		uuids := strings.Split(m.projectUUIDs, ",")
		payload["projectUuids"] = uuids
	case m.productUUID != "":
		payload["scopeType"] = "product"
		payload["scopeUuid"] = m.productUUID
		uuids := strings.Split(m.projectUUIDs, ",")
		payload["projectUuids"] = uuids
	case m.orgScopeUUID != "":
		payload["scopeType"] = "organization"
		payload["scopeUuid"] = m.orgScopeUUID
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3.0/projects/%s/dependencies/reports/SBOM",
		m.baseURL, m.projectUUID)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+m.jwtToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request SBOM export: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warning("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("export request failed (status %d): %s", resp.StatusCode, string(body))
	}

	var exportResp struct {
		Response struct {
			UUID string `json:"uuid"`
		} `json:"response"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&exportResp); err != nil {
		return fmt.Errorf("failed to parse export response: %w", err)
	}

	if exportResp.Response.UUID == "" {
		return fmt.Errorf("no report UUID in response")
	}

	logger.Info("Report UUID: %s", exportResp.Response.UUID)

	// Wait for report and download
	return m.downloadWhenReady(ctx, exportResp.Response.UUID, outputFile)
}

func (m *MendClient) downloadWhenReady(ctx context.Context, reportUUID, outputFile string) error {
	logger.Info("Waiting for SBOM report to be ready (UUID: %s)", reportUUID)
	logger.Info("Max wait time: %ds, Poll interval: %ds", m.maxWaitTime, m.pollInterval)

	startTime := time.Now()
	ticker := time.NewTicker(time.Duration(m.pollInterval) * time.Second)
	defer ticker.Stop()

	timeout := time.After(time.Duration(m.maxWaitTime) * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-timeout:
			return fmt.Errorf("timeout waiting for SBOM report after %ds", m.maxWaitTime)

		case <-ticker.C:
			elapsed := int(time.Since(startTime).Seconds())
			logger.Info("Checking report status... (elapsed: %ds)", elapsed)

			// Refresh token if needed (every 25 minutes)
			if elapsed > 0 && elapsed%1500 == 0 {
				logger.Info("Refreshing JWT token")
				if err := m.authenticate(ctx); err != nil {
					logger.Warning("Failed to refresh token: %v", err)
				}
			}

			status, err := m.checkReportStatus(ctx, reportUUID)
			if err != nil {
				logger.Warning("Failed to check status: %v", err)
				continue
			}

			logger.Info("Report status: %s", status)

			switch status {
			case "COMPLETED", "SUCCESS":
				logger.Success("Report is ready for download")
				return m.downloadReport(ctx, reportUUID, outputFile)

			case "FAILED", "CANCELED":
				return fmt.Errorf("report generation failed with status: %s", status)

			case "PENDING", "IN_PROGRESS":
				continue

			default:
				logger.Warning("Unknown report status: %s", status)
				continue
			}
		}
	}
}

func (m *MendClient) checkReportStatus(ctx context.Context, reportUUID string) (string, error) {
	url := fmt.Sprintf("%s/api/v3.0/orgs/%s/reports/%s", m.baseURL, m.orgUUID, reportUUID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+m.jwtToken)
	req.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warning("Failed to close response body: %v", err)
		}
	}()

	var statusResp struct {
		Response struct {
			Status string `json:"status"`
		} `json:"response"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		return "", err
	}

	return statusResp.Response.Status, nil
}

func (m *MendClient) downloadReport(ctx context.Context, reportUUID, outputFile string) error {
	logger.Info("Downloading SBOM report (UUID: %s)", reportUUID)

	url := fmt.Sprintf("%s/api/v3.0/orgs/%s/reports/download/%s",
		m.baseURL, m.orgUUID, reportUUID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+m.jwtToken)
	req.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(req)
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

	logger.Success("Mend SBOM downloaded successfully (%d bytes)", written)
	return nil
}
