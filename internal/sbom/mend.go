// Package sbom provides functionalities to interact with Mend API 3.0 for SBOM export.
package sbom

import (
	"archive/zip"
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

// mendJWTRefreshInterval is how long a Mend JWT is reused before a fresh login
// is performed during long report polls. Mend tokens expire after 30 minutes.
const mendJWTRefreshInterval = 25 * time.Minute

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

	url, payload, err := m.exportRequest()
	if err != nil {
		return err
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

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

// exportRequest builds the Mend API 3.0 SBOM export URL and JSON payload for
// the configured scope. Precedence mirrors the bash entrypoint: project, then
// product (which Mend API 3.0 calls an "application"), then organization.
//
// Field names are Mend API contract strings, so they are intentionally left as
// literals rather than extracted to constants.
func (m *MendClient) exportRequest() (string, map[string]interface{}, error) {
	payload := map[string]interface{}{
		"name":                   "clickbom-export", //nolint:goconst
		"reportType":             "cycloneDX_1_5",
		"format":                 "json",
		"includeVulnerabilities": false,
	}

	switch {
	case m.projectUUID != "":
		payload["scopeType"] = "project"
		payload["scopeUuid"] = m.projectUUID
		return fmt.Sprintf("%s/api/v3.0/projects/%s/dependencies/reports/SBOM", m.baseURL, m.projectUUID), payload, nil

	case m.productUUID != "":
		// Product-scoped export (Mend API 3.0 calls a product an "application"):
		//   POST /api/v3.0/applications/{applicationUuid}/dependencies/reports/SBOM
		// The documented body takes an optional projectUuids array to narrow the
		// export; when MEND_PROJECT_UUIDS is unset we omit it and export the whole
		// product. A previous version sent projectUuids: [""] (never a valid
		// selection) and maxDepthLevel: 0 (Mend documents the range as 1..4 and
		// rejects values outside it), so neither is sent any more.
		if uuids := splitUUIDList(m.projectUUIDs); len(uuids) > 0 {
			payload["projectUuids"] = uuids
		}
		return fmt.Sprintf("%s/api/v3.0/applications/%s/dependencies/reports/SBOM", m.baseURL, m.productUUID), payload, nil

	case m.orgScopeUUID != "":
		// Mend API 3.0 exposes dependency (SCA) SBOM exports only at project and
		// application scope (see https://api-docs.mend.io/platform/3.0/reports);
		// the organization-level SBOM endpoint exists solely for container-image
		// SBOMs. Fail fast instead of guessing a URL.
		return "", nil, fmt.Errorf("organization-scoped dependency SBOM exports are not offered by Mend API 3.0; set MEND_PROJECT_UUID or MEND_PRODUCT_UUID instead of MEND_ORG_SCOPE_UUID")
	}

	return "", nil, fmt.Errorf("no Mend scope configured: set MEND_PROJECT_UUID or MEND_PRODUCT_UUID")
}

// splitUUIDList turns the comma-separated MEND_PROJECT_UUIDS value into a slice,
// dropping empty entries so callers never emit "" as a UUID.
func splitUUIDList(list string) []string {
	if strings.TrimSpace(list) == "" {
		return nil
	}
	parts := strings.Split(list, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (m *MendClient) downloadWhenReady(ctx context.Context, reportUUID, outputFile string) error {
	logger.Info("Waiting for SBOM report to be ready (UUID: %s)", reportUUID)
	logger.Info("Max wait time: %ds, Poll interval: %ds", m.maxWaitTime, m.pollInterval)

	startTime := time.Now()
	lastAuth := startTime // authenticate() ran immediately before this loop
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

			// Mend JWTs expire after 30 minutes; refresh a little early. A
			// time-based check is used because the previous `elapsed%1500 == 0`
			// test only fired if the integer elapsed seconds happened to land
			// exactly on a multiple of 1500.
			if time.Since(lastAuth) >= mendJWTRefreshInterval {
				logger.Info("Refreshing JWT token")
				if err := m.authenticate(ctx); err != nil {
					logger.Warning("Failed to refresh token: %v", err)
				} else {
					lastAuth = time.Now()
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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("status check failed (status %d): %s", resp.StatusCode, string(body))
	}

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

	// After getting the response from Mend API
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Mend can return either a ZIP archive (typical) or the raw JSON SBOM
	// (older endpoints, or product/org-scoped requests). Sniff the magic
	// bytes and handle both — never silently succeed without writing output.
	if hasZipMagic(body) {
		extracted, err := extractFirstJSONFromZip(body)
		if err != nil {
			return err
		}
		body = extracted
	}

	if err := os.WriteFile(outputFile, body, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}
	if err := validateJSON(outputFile); err != nil {
		return fmt.Errorf("mend response is not valid JSON: %w", err)
	}
	logger.Success("Mend SBOM downloaded successfully (%d bytes)", len(body))
	return nil
}

// hasZipMagic reports whether the buffer starts with the "PK" ZIP signature.
func hasZipMagic(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x50 && b[1] == 0x4B
}

// extractFirstJSONFromZip returns the contents of the first *.json entry in the
// supplied ZIP archive. Used by Mend (single-report ZIPs always contain one
// SBOM JSON file).
func extractFirstJSONFromZip(body []byte) ([]byte, error) {
	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to read ZIP: %w", err)
	}
	for _, file := range zipReader.File {
		if !strings.HasSuffix(file.Name, ".json") {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open %s in ZIP: %w", file.Name, err)
		}
		defer func() { _ = rc.Close() }()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("ZIP contains no .json entries")
}
