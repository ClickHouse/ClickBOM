// Package storage provides functionalities to interact with storage backends like ClickHouse.
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ClickHouse/ClickBOM/internal/config"
	"github.com/ClickHouse/ClickBOM/pkg/logger"
)

// ClickHouseClient handles interactions with ClickHouse database.
type ClickHouseClient struct {
	url        string
	database   string
	username   string
	password   string
	truncate   bool
	httpClient *http.Client
}

// NewClickHouseClient creates a new ClickHouseClient with the provided configuration.
func NewClickHouseClient(cfg *config.Config) (*ClickHouseClient, error) {
	return &ClickHouseClient{
		url:      cfg.ClickHouseURL,
		database: cfg.ClickHouseDatabase,
		username: cfg.ClickHouseUsername,
		password: cfg.ClickHousePassword,
		truncate: cfg.TruncateTable,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}, nil
}

func (c *ClickHouseClient) executeQuery(ctx context.Context, query string) error {
	req, err := http.NewRequestWithContext(ctx, "POST", c.url, strings.NewReader(query))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	req.Header.Set("Content-Type", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warning("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("query failed (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *ClickHouseClient) queryScalar(ctx context.Context, query string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.url, strings.NewReader(query))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warning("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("query failed (status %d): %s", resp.StatusCode, string(body))
	}

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(result)), nil
}

// SetupTable prepares the ClickHouse table for data insertion.
func (c *ClickHouseClient) SetupTable(ctx context.Context, tableName string) error {
	logger.Info("Setting up ClickHouse table: %s", tableName)

	// Test connection
	logger.Debug("Testing ClickHouse connection...")
	if err := c.executeQuery(ctx, "SELECT 1"); err != nil {
		logger.Error("ClickHouse connection test failed")
		return fmt.Errorf("connection test failed: %w", err)
	}
	logger.Success("ClickHouse connection successful")

	// Check if table exists
	checkQuery := fmt.Sprintf(
		"SELECT COUNT(*) FROM system.tables WHERE database='%s' AND name='%s'",
		c.database, tableName)

	result, err := c.queryScalar(ctx, checkQuery)
	if err != nil {
		return fmt.Errorf("failed to check table existence: %w", err)
	}

	if result == "1" {
		logger.Info("Table %s already exists", tableName)

		// Check and migrate if needed
		if err := c.checkAndMigrateTable(ctx, tableName); err != nil {
			return fmt.Errorf("table migration failed: %w", err)
		}

		if c.truncate {
			logger.Info("Truncating existing table: %s", tableName)
			truncateQuery := fmt.Sprintf("TRUNCATE TABLE %s.%s", c.database, tableName)
			if err := c.executeQuery(ctx, truncateQuery); err != nil {
				return fmt.Errorf("failed to truncate table: %w", err)
			}
			logger.Success("Table %s truncated", tableName)
		} else {
			logger.Info("New data will be appended to existing table: %s", tableName)
		}
	} else {
		logger.Info("Creating new table: %s", tableName)
		createQuery := fmt.Sprintf(`
            CREATE TABLE %s.%s (
                name String,
                version String,
                license String,
                source LowCardinality(String),
                inserted_at DateTime DEFAULT now()
            ) ENGINE = MergeTree()
            ORDER BY (name, version, license)
        `, c.database, tableName)

		if err := c.executeQuery(ctx, createQuery); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
		logger.Success("Table %s created successfully", tableName)
	}

	return nil
}

func (c *ClickHouseClient) checkAndMigrateTable(ctx context.Context, tableName string) error {
	logger.Info("Checking if table %s needs migration for source column", tableName)

	// Check if source column exists
	checkQuery := fmt.Sprintf(
		"SELECT COUNT(*) FROM system.columns WHERE database='%s' AND table='%s' AND name='source'",
		c.database, tableName)

	result, err := c.queryScalar(ctx, checkQuery)
	if err != nil {
		return fmt.Errorf("failed to check column existence: %w", err)
	}

	if result == "0" {
		logger.Info("source column not found, migrating table: %s", tableName)

		alterQuery := fmt.Sprintf(
			"ALTER TABLE %s.%s ADD COLUMN source LowCardinality(String) DEFAULT 'unknown'",
			c.database, tableName)

		if err := c.executeQuery(ctx, alterQuery); err != nil {
			return fmt.Errorf("failed to add source column: %w", err)
		}

		logger.Success("source column added to table %s", tableName)
	} else {
		logger.Info("source column already exists in table %s", tableName)
	}

	return nil
}

// InsertSBOMData extracts components from the SBOM and inserts them into the ClickHouse table.
func (c *ClickHouseClient) InsertSBOMData(ctx context.Context, sbomFile, tableName, sbomFormat string) error {
	logger.Info("Extracting components from %s SBOM for ClickHouse", sbomFormat)

	// Read SBOM file
	data, err := os.ReadFile(sbomFile)
	if err != nil {
		return fmt.Errorf("failed to read SBOM file: %w", err)
	}

	var components []map[string]interface{}

	// Parse based on format
	switch sbomFormat {
	case "cyclonedx":
		var cdx struct {
			Components []map[string]interface{} `json:"components"`
		}
		if err := json.Unmarshal(data, &cdx); err != nil {
			return fmt.Errorf("failed to parse CycloneDX: %w", err)
		}
		components = cdx.Components

	case "spdxjson":
		var spdx struct {
			Packages []map[string]interface{} `json:"packages"`
		}
		if err := json.Unmarshal(data, &spdx); err != nil {
			return fmt.Errorf("failed to parse SPDX: %w", err)
		}
		components = spdx.Packages

	default:
		return fmt.Errorf("unsupported SBOM format: %s", sbomFormat)
	}

	if len(components) == 0 {
		logger.Warning("No components found in SBOM")
		return nil
	}

	logger.Info("Found %d components to insert", len(components))

	// Build TSV data
	var tsvData bytes.Buffer
	for _, comp := range components {
		name := getStringField(comp, "name", "unknown")
		version := getStringField(comp, "version", "unknown")
		license := extractLicense(comp)
		source := getStringField(comp, "source", "unknown")

		fmt.Fprintf(&tsvData, "%s\t%s\t%s\t%s\n", name, version, license, source)
	}

	// Insert data
	insertURL := fmt.Sprintf("%s/?query=%s",
		c.url,
		url.QueryEscape(fmt.Sprintf(
			"INSERT INTO %s.%s (name, version, license, source) FORMAT TSV",
			c.database, tableName)))

	req, err := http.NewRequestWithContext(ctx, "POST", insertURL, &tsvData)
	if err != nil {
		return fmt.Errorf("failed to create insert request: %w", err)
	}

	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	req.Header.Set("Content-Type", "text/tab-separated-values")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("insert request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warning("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("insert failed (status %d): %s", resp.StatusCode, string(body))
	}

	logger.Success("Inserted %d components into ClickHouse table %s", len(components), tableName)
	return nil
}

func getStringField(m map[string]interface{}, key, defaultVal string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultVal
}

func extractLicense(comp map[string]interface{}) string {
	// Try CycloneDX licenses array
	if licenses, ok := comp["licenses"].([]interface{}); ok && len(licenses) > 0 {
		if lic, ok := licenses[0].(map[string]interface{}); ok {
			if license, ok := lic["license"].(map[string]interface{}); ok {
				if id, ok := license["id"].(string); ok && id != "" {
					return id
				}
				if name, ok := license["name"].(string); ok && name != "" {
					return name
				}
			}
		}
	}

	// Try SPDX fields
	if concluded, ok := comp["licenseConcluded"].(string); ok && concluded != "" {
		return concluded
	}
	if declared, ok := comp["licenseDeclared"].(string); ok && declared != "" {
		return declared
	}

	return "unknown"
}
