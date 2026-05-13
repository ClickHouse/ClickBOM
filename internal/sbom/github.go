// Package sbom provides functionalities to interact with GitHub API for SBOM download.
package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ClickHouse/ClickBOM/pkg/logger"
)

// GitHubClient handles interactions with the GitHub API.
type GitHubClient struct {
	token      string
	httpClient *http.Client
}

// NewGitHubClient creates a new GitHubClient with the provided token.
func NewGitHubClient(token string) *GitHubClient {
	return &GitHubClient{
		token: token,
		httpClient: &http.Client{
			Timeout: 10 * time.Minute,
		},
	}
}

// DownloadSBOM downloads the SBOM from the specified GitHub repository.
func (g *GitHubClient) DownloadSBOM(ctx context.Context, repo, outputFile string) error {
	logger.Info("Downloading SBOM from %s", repo)

	url := fmt.Sprintf("https://api.github.com/repos/%s/dependency-graph/sbom", repo)

	maxAttempts := 3
	baseDelay := 30 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		logger.Info("Starting SBOM download, attempt %d/%d", attempt, maxAttempts)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", g.token))
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		resp, err := g.httpClient.Do(req)
		if err != nil {
			if attempt < maxAttempts {
				delay := baseDelay * time.Duration(attempt)
				logger.Warning("Request failed, waiting %v before retry: %v", delay, err)
				time.Sleep(delay)
				continue
			}
			return fmt.Errorf("failed to download SBOM after %d attempts: %w", maxAttempts, err)
		}

		body, err := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Warning("Failed to close response body: %v", closeErr)
		}
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			if msg, ok := retryableGitHubMessage(body); ok && attempt < maxAttempts {
				delay := baseDelay * time.Duration(attempt)
				logger.Warning("GitHub SBOM generation transient error on attempt %d: %s", attempt, msg)
				logger.Info("Waiting %v before retry...", delay)
				time.Sleep(delay)
				continue
			}
			return fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(body))
		}

		// GitHub sometimes returns 200 with a JSON body containing a transient
		// `.message` (timeout, generation failure). Detect and retry — bash does
		// the same check before writing the file.
		if msg, ok := retryableGitHubMessage(body); ok {
			if attempt < maxAttempts {
				delay := baseDelay * time.Duration(attempt)
				logger.Warning("GitHub 200 with transient error on attempt %d: %s", attempt, msg)
				logger.Info("Waiting %v before retry...", delay)
				time.Sleep(delay)
				continue
			}
			return fmt.Errorf("GitHub SBOM generation failed after %d attempts: %s", maxAttempts, msg)
		}

		if err := os.WriteFile(outputFile, body, 0644); err != nil {
			return fmt.Errorf("failed to write SBOM to file: %w", err)
		}

		logger.Success("SBOM downloaded successfully (%d bytes) on attempt %d", len(body), attempt)

		// Validate JSON
		if err := validateJSON(outputFile); err != nil {
			if attempt < maxAttempts {
				delay := baseDelay * time.Duration(attempt)
				logger.Warning("Downloaded file is not valid JSON on attempt %d", attempt)
				time.Sleep(delay)
				continue
			}
			return fmt.Errorf("downloaded file is not valid JSON after all attempts: %w", err)
		}

		return nil
	}

	return fmt.Errorf("failed to download SBOM after %d attempts", maxAttempts)
}

// retryableGitHubMessage inspects a response body for a JSON `.message` field
// matching a known transient error pattern. Returns the message and whether
// it should trigger a retry.
func retryableGitHubMessage(body []byte) (string, bool) {
	var probe struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "", false
	}
	if probe.Message == "" {
		return "", false
	}
	return probe.Message, isRetryableError(probe.Message)
}

func isRetryableError(message string) bool {
	retryableMessages := []string{
		"Request timed out",
		"Failed to generate SBOM",
		"timeout",
	}
	for _, msg := range retryableMessages {
		if strings.Contains(message, msg) {
			return true
		}
	}
	return false
}

func validateJSON(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var js json.RawMessage
	if err := json.Unmarshal(data, &js); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}
