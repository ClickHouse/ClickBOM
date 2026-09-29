// Package config handles loading and validating configuration from environment variables.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/ClickHouse/ClickBOM/internal/validation"
)

// SBOM source identifiers used across the codebase.
const (
	SourceGitHub = "github"
	SourceMend   = "mend"
	SourceWiz    = "wiz"
	SourceTrivy  = "trivy"
)

// SLACK_NOTIFY_ON values: post every outcome, or failures only.
const (
	SlackNotifyAlways    = "always"
	SlackNotifyOnFailure = "failure"
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

	// Trivy
	TrivyImage         string
	TrivyECRAccountID  string
	TrivyECRRegion     string
	TrivyECRRoleARN    string
	TrivyECRExternalID string
	TrivyFormat        string

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

	// License mapping
	LicenseMappingFile string

	// Notifications
	SlackWebhookURL string // Slack incoming webhook; a credential, never logged
	SlackNotifyOn   string // SlackNotifyAlways or SlackNotifyOnFailure
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() (*Config, error) {
	truncate, err := validation.SanitizeBool(os.Getenv("TRUNCATE_TABLE"), "TRUNCATE_TABLE", false)
	if err != nil {
		return nil, err
	}
	merge, err := validation.SanitizeBool(os.Getenv("MERGE"), "MERGE", false)
	if err != nil {
		return nil, err
	}
	debug, err := validation.SanitizeBool(os.Getenv("DEBUG"), "DEBUG", false)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		// AWS (required)
		S3Bucket: os.Getenv("S3_BUCKET"),
		S3Key:    getEnvOrDefault("S3_KEY", "sbom.json"),

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

		// Trivy
		TrivyImage:         getEnvOrDefault("TRIVY_IMAGE", ""),
		TrivyECRAccountID:  getEnvOrDefault("TRIVY_ECR_ACCOUNT_ID", ""),
		TrivyECRRegion:     getEnvOrDefault("TRIVY_ECR_REGION", "us-east-1"),
		TrivyECRRoleARN:    getEnvOrDefault("TRIVY_ECR_ROLE_ARN", ""),
		TrivyECRExternalID: getEnvOrDefault("TRIVY_ECR_EXTERNAL_ID", ""),
		TrivyFormat:        getEnvOrDefault("TRIVY_FORMAT", "cyclonedx"),

		// ClickHouse
		ClickHouseURL:      os.Getenv("CLICKHOUSE_URL"),
		ClickHouseDatabase: getEnvOrDefault("CLICKHOUSE_DATABASE", "default"),
		ClickHouseUsername: getEnvOrDefault("CLICKHOUSE_USERNAME", "default"),
		ClickHousePassword: os.Getenv("CLICKHOUSE_PASSWORD"),
		TruncateTable:      truncate,

		// General
		SBOMSource:         getEnvOrDefault("SBOM_SOURCE", "github"),
		SBOMFormat:         getEnvOrDefault("SBOM_FORMAT", "cyclonedx"),
		Merge:              merge,
		Include:            os.Getenv("INCLUDE"),
		Exclude:            os.Getenv("EXCLUDE"),
		Debug:              debug,
		LicenseMappingFile: getEnvOrDefault("LICENSE_MAPPING_FILE", "/app/license-mappings.json"),

		// Notifications
		SlackWebhookURL: os.Getenv("SLACK_WEBHOOK_URL"),
		SlackNotifyOn:   getEnvOrDefault("SLACK_NOTIFY_ON", SlackNotifyAlways),
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
	if c.S3Bucket == "" {
		return fmt.Errorf("S3_BUCKET is required")
	}

	// Repository required if not in merge mode and source is GitHub
	if !c.Merge && c.SBOMSource != SourceMend && c.SBOMSource != SourceWiz && c.SBOMSource != SourceTrivy {
		if c.Repository == "" {
			return fmt.Errorf("REPOSITORY is required when not in merge mode")
		}
	}

	// Mend validation
	if c.SBOMSource == SourceMend {
		if c.MendEmail == "" {
			return fmt.Errorf("MEND_EMAIL is required for Mend source")
		}
		if c.MendOrgUUID == "" {
			return fmt.Errorf("MEND_ORG_UUID is required for Mend source")
		}
		if c.MendUserKey == "" {
			return fmt.Errorf("MEND_USER_KEY is required for Mend source")
		}
		// Mend API 3.0 only offers dependency SBOM exports at project and
		// product ("application") scope, so MEND_ORG_SCOPE_UUID alone is not a
		// usable configuration.
		if c.MendProjectUUID == "" && c.MendProductUUID == "" {
			return fmt.Errorf("at least one of MEND_PROJECT_UUID or MEND_PRODUCT_UUID is required for Mend source (organization-scoped dependency SBOM exports are not offered by Mend API 3.0)")
		}
	}

	// Wiz validation
	if c.SBOMSource == SourceWiz {
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

	// Trivy validation
	if c.SBOMSource == SourceTrivy {
		if c.TrivyImage == "" {
			return fmt.Errorf("TRIVY_IMAGE is required for Trivy source")
		}
		if c.TrivyFormat != "cyclonedx" && c.TrivyFormat != "spdxjson" {
			return fmt.Errorf("TRIVY_FORMAT must be 'cyclonedx' or 'spdxjson'")
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

// sanitizeURLs validates and rewrites every URL field on the config. Extracted
// from Sanitize so the parent stays under the project cyclo limit.
func (c *Config) sanitizeURLs() error {
	urls := []struct {
		ptr  *string
		kind string
	}{
		{&c.MendBaseURL, "mend"},
		{&c.WizAuthEndpoint, "wiz"},
		{&c.WizAPIEndpoint, "wiz"},
		{&c.ClickHouseURL, "clickhouse"},
	}
	for _, u := range urls {
		if *u.ptr == "" {
			continue
		}
		clean, err := validation.SanitizeURL(*u.ptr, u.kind)
		if err != nil {
			return err
		}
		*u.ptr = clean
	}
	return nil
}

// sanitizeUUIDs validates and rewrites every Mend UUID field on the config.
func (c *Config) sanitizeUUIDs() error {
	uuids := []struct {
		ptr   *string
		field string
	}{
		{&c.MendOrgUUID, "MEND_ORG_UUID"},
		{&c.MendProjectUUID, "MEND_PROJECT_UUID"},
		{&c.MendProductUUID, "MEND_PRODUCT_UUID"},
		{&c.MendOrgScopeUUID, "MEND_ORG_SCOPE_UUID"},
	}
	for _, u := range uuids {
		if *u.ptr == "" {
			continue
		}
		clean, err := validation.SanitizeUUID(*u.ptr, u.field)
		if err != nil {
			return err
		}
		*u.ptr = clean
	}
	if c.MendProjectUUIDs != "" {
		clean, err := validation.SanitizeUUIDList(c.MendProjectUUIDs, "MEND_PROJECT_UUIDS")
		if err != nil {
			return err
		}
		c.MendProjectUUIDs = clean
	}
	return nil
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

	if err := c.sanitizeURLs(); err != nil {
		return err
	}

	// The Slack webhook is a credential, so it has its own validator whose
	// error never echoes the value (SanitizeURL quotes the URL it rejects).
	if c.SlackWebhookURL != "" {
		c.SlackWebhookURL, err = validation.SanitizeSlackWebhookURL(c.SlackWebhookURL)
		if err != nil {
			return err
		}
	}
	// SLACK_NOTIFY_ON is a closed set. It is not sensitive, so the rejected
	// value may be quoted. Empty (a Config built without LoadConfig) means
	// always, which is also the action.yml default.
	switch strings.ToLower(strings.TrimSpace(c.SlackNotifyOn)) {
	case "", SlackNotifyAlways:
		c.SlackNotifyOn = SlackNotifyAlways
	case SlackNotifyOnFailure:
		c.SlackNotifyOn = SlackNotifyOnFailure
	default:
		return fmt.Errorf("invalid SLACK_NOTIFY_ON: %q (must be always or failure)", c.SlackNotifyOn)
	}
	if err := c.sanitizeUUIDs(); err != nil {
		return err
	}

	// Numeric ranges (bash entrypoint enforces 60-7200 and 10-300).
	if _, err := validation.SanitizeNumeric(fmt.Sprintf("%d", c.MendMaxWaitTime), "MEND_MAX_WAIT_TIME", 60, 7200); err != nil {
		return err
	}
	if _, err := validation.SanitizeNumeric(fmt.Sprintf("%d", c.MendPollInterval), "MEND_POLL_INTERVAL", 10, 300); err != nil {
		return err
	}

	// SBOM source / format are closed sets.
	switch c.SBOMSource {
	case SourceGitHub, SourceMend, SourceWiz, SourceTrivy:
	default:
		return fmt.Errorf("invalid SBOM_SOURCE: %q (must be github, mend, wiz, or trivy)", c.SBOMSource)
	}
	switch c.SBOMFormat {
	case "cyclonedx", "spdxjson":
	default:
		return fmt.Errorf("invalid SBOM_FORMAT: %q (must be cyclonedx or spdxjson)", c.SBOMFormat)
	}

	// ClickHouse database identifier must be SQL-legal.
	if c.ClickHouseDatabase != "" {
		c.ClickHouseDatabase = validation.SanitizeDatabaseName(c.ClickHouseDatabase)
		if c.ClickHouseDatabase == "" {
			return fmt.Errorf("CLICKHOUSE_DATABASE is empty after sanitization")
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

// sensitiveEnvVars lists every environment variable whose value the README
// marks Sensitive, plus the AWS credentials that arrive as job env rather than
// as inputs. Keep it in sync with the README input tables: these values are
// what the Slack notifier redacts from error text before posting.
var sensitiveEnvVars = []string{
	"GITHUB_TOKEN",
	"MEND_EMAIL", "MEND_ORG_UUID", "MEND_USER_KEY",
	"MEND_PROJECT_UUID", "MEND_PRODUCT_UUID", "MEND_ORG_SCOPE_UUID", "MEND_PROJECT_UUIDS",
	"WIZ_AUTH_ENDPOINT", "WIZ_API_ENDPOINT", "WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET", "WIZ_REPORT_ID",
	"TRIVY_ECR_EXTERNAL_ID",
	"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
	"CLICKHOUSE_URL", "CLICKHOUSE_PASSWORD",
	"SLACK_WEBHOOK_URL",
}

// SecretsFromEnv returns the raw values of every sensitive environment
// variable. The one list-valued variable, MEND_PROJECT_UUIDS, contributes the
// whole value and each comma-separated element, because validation errors
// echo a single entry. It needs no Config, so it also serves runs whose
// configuration failed to load, and it should be called early: Trivy's
// AssumeRole rewrites the AWS_* variables mid-run.
func SecretsFromEnv() []string {
	var out []string
	for _, name := range sensitiveEnvVars {
		v := os.Getenv(name)
		out = appendNonEmpty(out, v)
		if name == "MEND_PROJECT_UUIDS" {
			out = appendNonEmpty(out, strings.Split(v, ",")...)
		}
	}
	return out
}

// SensitiveEnvVars returns a copy of the sensitive variable names so tests and
// tooling can isolate them.
func SensitiveEnvVars() []string {
	return append([]string(nil), sensitiveEnvVars...)
}

// Secrets returns every configuration value that must never appear in a
// notification: the sanitized sensitive fields (which may differ from the raw
// input) plus the raw environment values they came from. AWSAccessKeyID and
// AWSSecretAccessKey are not listed because LoadConfig never populates them;
// SecretsFromEnv covers the job's AWS credentials.
func (c *Config) Secrets() []string {
	out := appendNonEmpty(nil,
		c.GitHubToken,
		c.MendEmail, c.MendOrgUUID, c.MendUserKey,
		c.MendProjectUUID, c.MendProductUUID, c.MendOrgScopeUUID,
		c.WizAuthEndpoint, c.WizAPIEndpoint, c.WizClientID, c.WizClientSecret, c.WizReportID,
		c.TrivyECRExternalID,
		c.ClickHouseURL, c.ClickHousePassword,
		c.SlackWebhookURL,
	)
	out = appendNonEmpty(out, strings.Split(c.MendProjectUUIDs, ",")...)
	if c.ClickHousePassword != "" {
		// Every ClickHouse request carries `Authorization: Basic <base64>`; an
		// intermediary that echoes request headers would leak that spelling.
		out = append(out, base64.StdEncoding.EncodeToString([]byte(c.ClickHouseUsername+":"+c.ClickHousePassword)))
	}
	return append(out, SecretsFromEnv()...)
}

// SlackWebhookURLFromEnv validates SLACK_WEBHOOK_URL on its own, for the path
// where LoadConfig has already rejected the configuration as a whole.
func SlackWebhookURLFromEnv() (string, error) {
	return validation.SanitizeSlackWebhookURL(os.Getenv("SLACK_WEBHOOK_URL"))
}

func appendNonEmpty(out []string, values ...string) []string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
