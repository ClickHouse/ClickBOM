// Package config handles loading and validating configuration from environment variables.
package config

import (
	"fmt"
	"os"

	"github.com/ClickHouse/ClickBOM/internal/validation"
)

// Config holds the application configuration.
type Config struct {
	// GitHub
	GitHubToken string
	Repository  string

	// Mend
	MendEmail        string
	MendOrgUUID      string
	MendUserKey      string
	MendBaseURL      string
	MendProjectUUID  string
	MendProductUUID  string
	MendOrgScopeUUID string
	MendProjectUUIDs string
	MendMaxWaitTime  int
	MendPollInterval int

	// Wiz
	WizAuthEndpoint string
	WizAPIEndpoint  string
	WizClientID     string
	WizClientSecret string
	WizReportID     string

	// AWS
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSRegion          string
	S3Bucket           string
	S3Key              string

	// ClickHouse
	ClickHouseURL      string
	ClickHouseDatabase string
	ClickHouseUsername string
	ClickHousePassword string
	TruncateTable      bool

	// General
	SBOMSource string // "github", "mend", "wiz"
	SBOMFormat string // "cyclonedx", "spdxjson"
	Merge      bool
	Include    string
	Exclude    string
	Debug      bool
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		// AWS (required)
		AWSAccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		AWSRegion:          getEnvOrDefault("AWS_DEFAULT_REGION", "us-east-1"),
		S3Bucket:           os.Getenv("S3_BUCKET"),
		S3Key:              getEnvOrDefault("S3_KEY", "sbom.json"),

		// GitHub
		GitHubToken: os.Getenv("GITHUB_TOKEN"),
		Repository:  os.Getenv("REPOSITORY"),

		// Mend
		MendEmail:        os.Getenv("MEND_EMAIL"),
		MendOrgUUID:      os.Getenv("MEND_ORG_UUID"),
		MendUserKey:      os.Getenv("MEND_USER_KEY"),
		MendBaseURL:      getEnvOrDefault("MEND_BASE_URL", "https://api-saas.mend.io"),
		MendProjectUUID:  os.Getenv("MEND_PROJECT_UUID"),
		MendProductUUID:  os.Getenv("MEND_PRODUCT_UUID"),
		MendOrgScopeUUID: os.Getenv("MEND_ORG_SCOPE_UUID"),
		MendProjectUUIDs: os.Getenv("MEND_PROJECT_UUIDS"),
		MendMaxWaitTime:  getEnvAsInt("MEND_MAX_WAIT_TIME", 1800),
		MendPollInterval: getEnvAsInt("MEND_POLL_INTERVAL", 30),

		// Wiz
		WizAuthEndpoint: os.Getenv("WIZ_AUTH_ENDPOINT"),
		WizAPIEndpoint:  os.Getenv("WIZ_API_ENDPOINT"),
		WizClientID:     os.Getenv("WIZ_CLIENT_ID"),
		WizClientSecret: os.Getenv("WIZ_CLIENT_SECRET"),
		WizReportID:     os.Getenv("WIZ_REPORT_ID"),

		// ClickHouse
		ClickHouseURL:      os.Getenv("CLICKHOUSE_URL"),
		ClickHouseDatabase: getEnvOrDefault("CLICKHOUSE_DATABASE", "default"),
		ClickHouseUsername: getEnvOrDefault("CLICKHOUSE_USERNAME", "default"),
		ClickHousePassword: os.Getenv("CLICKHOUSE_PASSWORD"),
		TruncateTable:      getEnvAsBool("TRUNCATE_TABLE", false),

		// General
		SBOMSource: getEnvOrDefault("SBOM_SOURCE", "github"),
		SBOMFormat: getEnvOrDefault("SBOM_FORMAT", "cyclonedx"),
		Merge:      getEnvAsBool("MERGE", false),
		Include:    os.Getenv("INCLUDE"),
		Exclude:    os.Getenv("EXCLUDE"),
		Debug:      getEnvAsBool("DEBUG", false),
	}

	// Sanitize inputs
	if err := cfg.Sanitize(); err != nil {
		return nil, fmt.Errorf("sanitization failed: %w", err)
	}

	// Validate required fields
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return cfg, nil
}

// Validate checks that all required configuration fields are set appropriately.
func (c *Config) Validate() error {
	// AWS is always required
	if c.AWSAccessKeyID == "" {
		return fmt.Errorf("AWS_ACCESS_KEY_ID is required")
	}
	if c.AWSSecretAccessKey == "" {
		return fmt.Errorf("AWS_SECRET_ACCESS_KEY is required")
	}
	if c.S3Bucket == "" {
		return fmt.Errorf("S3_BUCKET is required")
	}

	// Repository required if not in merge mode and source is GitHub
	if !c.Merge && c.SBOMSource != "mend" && c.SBOMSource != "wiz" {
		if c.Repository == "" {
			return fmt.Errorf("REPOSITORY is required when not in merge mode")
		}
	}

	// Mend validation
	if c.SBOMSource == "mend" {
		if c.MendEmail == "" {
			return fmt.Errorf("MEND_EMAIL is required for Mend source")
		}
		if c.MendOrgUUID == "" {
			return fmt.Errorf("MEND_ORG_UUID is required for Mend source")
		}
		if c.MendUserKey == "" {
			return fmt.Errorf("MEND_USER_KEY is required for Mend source")
		}
		if c.MendProjectUUID == "" && c.MendProductUUID == "" {
			return fmt.Errorf("at least one of MEND_PROJECT_UUID or MEND_PRODUCT_UUID is required")
		}
	}

	// Wiz validation
	if c.SBOMSource == "wiz" {
		if c.WizAPIEndpoint == "" {
			return fmt.Errorf("WIZ_API_ENDPOINT is required for Wiz source")
		}
		if c.WizClientID == "" {
			return fmt.Errorf("WIZ_CLIENT_ID is required for Wiz source")
		}
		if c.WizClientSecret == "" {
			return fmt.Errorf("WIZ_CLIENT_SECRET is required for Wiz source")
		}
		if c.WizReportID == "" {
			return fmt.Errorf("WIZ_REPORT_ID is required for Wiz source")
		}
	}

	// ClickHouse validation
	if c.ClickHouseURL != "" {
		if c.ClickHouseDatabase == "" {
			return fmt.Errorf("CLICKHOUSE_DATABASE is required when using ClickHouse")
		}
		if c.ClickHouseUsername == "" {
			return fmt.Errorf("CLICKHOUSE_USERNAME is required when using ClickHouse")
		}
	}

	return nil
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvAsInt(key string, defaultVal int) int {
	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultVal
	}
	var val int
	_, err := fmt.Sscanf(valStr, "%d", &val)
	if err != nil {
		return defaultVal
	}
	return val
}

func getEnvAsBool(key string, defaultVal bool) bool {
	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultVal
	}
	return valStr == "true"
}

// Sanitize cleans and validates configuration fields.
func (c *Config) Sanitize() error {
	var err error

	// Repository
	if c.Repository != "" {
		c.Repository, err = validation.SanitizeRepository(c.Repository)
		if err != nil {
			return err
		}
	}

	// Email
	if c.MendEmail != "" {
		c.MendEmail, err = validation.SanitizeEmail(c.MendEmail)
		if err != nil {
			return err
		}
	}

	// S3
	if c.S3Bucket != "" {
		c.S3Bucket, err = validation.SanitizeS3Bucket(c.S3Bucket)
		if err != nil {
			return err
		}
	}

	if c.S3Key != "" {
		c.S3Key, err = validation.SanitizeS3Key(c.S3Key)
		if err != nil {
			return err
		}
	}

	// URLs
	if c.MendBaseURL != "" {
		c.MendBaseURL, err = validation.SanitizeURL(c.MendBaseURL, "mend")
		if err != nil {
			return err
		}
	}

	if c.WizAuthEndpoint != "" {
		c.WizAuthEndpoint, err = validation.SanitizeURL(c.WizAuthEndpoint, "wiz")
		if err != nil {
			return err
		}
	}

	if c.WizAPIEndpoint != "" {
		c.WizAPIEndpoint, err = validation.SanitizeURL(c.WizAPIEndpoint, "wiz")
		if err != nil {
			return err
		}
	}

	if c.ClickHouseURL != "" {
		c.ClickHouseURL, err = validation.SanitizeURL(c.ClickHouseURL, "clickhouse")
		if err != nil {
			return err
		}
	}

	// UUIDs
	if c.MendOrgUUID != "" {
		c.MendOrgUUID, err = validation.SanitizeUUID(c.MendOrgUUID, "MEND_ORG_UUID")
		if err != nil {
			return err
		}
	}

	if c.MendProjectUUID != "" {
		c.MendProjectUUID, err = validation.SanitizeUUID(c.MendProjectUUID, "MEND_PROJECT_UUID")
		if err != nil {
			return err
		}
	}

	if c.MendProductUUID != "" {
		c.MendProductUUID, err = validation.SanitizeUUID(c.MendProductUUID, "MEND_PRODUCT_UUID")
		if err != nil {
			return err
		}
	}

	// Patterns
	c.Include = validation.SanitizePatterns(c.Include)
	c.Exclude = validation.SanitizePatterns(c.Exclude)

	// Sanitize strings with length limits
	c.GitHubToken = validation.SanitizeString(c.GitHubToken, 1000)
	c.MendUserKey = validation.SanitizeString(c.MendUserKey, 500)
	c.WizClientID = validation.SanitizeString(c.WizClientID, 200)
	c.WizClientSecret = validation.SanitizeString(c.WizClientSecret, 500)
	c.WizReportID = validation.SanitizeString(c.WizReportID, 200)
	c.AWSAccessKeyID = validation.SanitizeString(c.AWSAccessKeyID, 100)
	c.AWSSecretAccessKey = validation.SanitizeString(c.AWSSecretAccessKey, 500)
	c.ClickHousePassword = validation.SanitizeString(c.ClickHousePassword, 500)

	return nil
}
