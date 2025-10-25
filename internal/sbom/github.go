// Package sbom provides functionalities to interact with GitHub API for SBOM download.
package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

		defer func() {
			if err := resp.Body.Close(); err != nil {
				logger.Warning("Failed to close response body: %v", err)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)

			// Check for retryable errors
			var errResp struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(body, &errResp) == nil {
				if isRetryableError(errResp.Message) && attempt < maxAttempts {
					delay := baseDelay * time.Duration(attempt)
					logger.Warning("GitHub SBOM generation timed out on attempt %d: %s", attempt, errResp.Message)
					logger.Info("Waiting %v before retry...", delay)
					time.Sleep(delay)
					continue
				}
			}

			return fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(body))
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
			return fmt.Errorf("failed to write SBOM to file: %w", err)
		}

		logger.Success("SBOM downloaded successfully (%d bytes) on attempt %d", written, attempt)

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

func isRetryableError(message string) bool {
	retryableMessages := []string{
		"Request timed out",
		"Failed to generate SBOM",
		"timeout",
	}

	for _, msg := range retryableMessages {
		if contains(message, msg) {
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

func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
