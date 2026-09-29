package config

import (
	"encoding/base64"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{
			name: "valid minimal config",
			env: map[string]string{
				"S3_BUCKET":  "test-bucket",
				"REPOSITORY": "owner/repo",
			},
			wantErr: false,
		},
		{
			name: "missing required field",
			env: map[string]string{
				// Missing S3_BUCKET
				"REPOSITORY": "owner/repo",
			},
			wantErr: true,
		},
		{
			name: "invalid repository format",
			env: map[string]string{
				"S3_BUCKET":  "test-bucket",
				"REPOSITORY": "invalid-repo", // No slash
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			os.Clearenv()

			// Set test environment
			for k, v := range tt.env {
				err := os.Setenv(k, v)
				if err != nil {
					t.Fatalf("Failed to set env var %s: %v", k, err)
				}
			}

			cfg, err := LoadConfig()

			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && cfg == nil {
				t.Error("LoadConfig() returned nil config")
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid github config",
			config: &Config{
				S3Bucket:   "bucket",
				Repository: "owner/repo",
				SBOMSource: "github",
			},
			wantErr: false,
		},
		{
			name: "valid mend config",
			config: &Config{
				S3Bucket:        "bucket",
				SBOMSource:      "mend",
				MendEmail:       "test@example.com",
				MendOrgUUID:     "123e4567-e89b-12d3-a456-426614174000",
				MendUserKey:     "user-key",
				MendProjectUUID: "123e4567-e89b-12d3-a456-426614174001",
			},
			wantErr: false,
		},
		{
			name: "invalid mend config - org scope only is not exportable",
			config: &Config{
				S3Bucket:         "bucket",
				SBOMSource:       "mend",
				MendEmail:        "test@example.com",
				MendOrgUUID:      "123e4567-e89b-12d3-a456-426614174000",
				MendUserKey:      "user-key",
				MendOrgScopeUUID: "123e4567-e89b-12d3-a456-426614174002",
			},
			wantErr: true,
		},
		{
			name: "valid mend config - product scope only",
			config: &Config{
				S3Bucket:        "bucket",
				SBOMSource:      "mend",
				MendEmail:       "test@example.com",
				MendOrgUUID:     "123e4567-e89b-12d3-a456-426614174000",
				MendUserKey:     "user-key",
				MendProductUUID: "123e4567-e89b-12d3-a456-426614174003",
			},
			wantErr: false,
		},
		{
			name: "invalid mend config - no scope at all",
			config: &Config{
				S3Bucket:    "bucket",
				SBOMSource:  "mend",
				MendEmail:   "test@example.com",
				MendOrgUUID: "123e4567-e89b-12d3-a456-426614174000",
				MendUserKey: "user-key",
			},
			wantErr: true,
		},
		{
			name: "invalid mend config - missing email",
			config: &Config{
				S3Bucket:   "bucket",
				SBOMSource: "mend",
				// Missing MendEmail
				MendOrgUUID:     "123e4567-e89b-12d3-a456-426614174000",
				MendUserKey:     "user-key",
				MendProjectUUID: "123e4567-e89b-12d3-a456-426614174001",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func setEnv(t *testing.T, env map[string]string) {
	t.Helper()
	os.Clearenv()
	for k, v := range env {
		if err := os.Setenv(k, v); err != nil {
			t.Fatalf("setenv %s: %v", k, err)
		}
	}
}

func TestLoadConfig_RejectsBadBoolean(t *testing.T) {
	for _, key := range []string{"TRUNCATE_TABLE", "MERGE", "DEBUG"} {
		t.Run(key+"=yes", func(t *testing.T) {
			setEnv(t, map[string]string{
				"S3_BUCKET":  "test-bucket",
				"REPOSITORY": "owner/repo",
				key:          "yes",
			})
			if _, err := LoadConfig(); err == nil {
				t.Errorf("LoadConfig accepted %s=yes; want error", key)
			}
		})
	}
}

func TestLoadConfig_AcceptsTrueFalse(t *testing.T) {
	setEnv(t, map[string]string{
		"S3_BUCKET":      "test-bucket",
		"REPOSITORY":     "owner/repo",
		"TRUNCATE_TABLE": "true",
		"MERGE":          "false",
		"DEBUG":          "true",
	})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.TruncateTable || cfg.Merge || !cfg.Debug {
		t.Errorf("bools wrong: TruncateTable=%v Merge=%v Debug=%v", cfg.TruncateTable, cfg.Merge, cfg.Debug)
	}
}

func TestLoadConfig_RejectsBadSBOMSourceAndFormat(t *testing.T) {
	t.Run("bad source", func(t *testing.T) {
		setEnv(t, map[string]string{
			"S3_BUCKET":   "test-bucket",
			"REPOSITORY":  "owner/repo",
			"SBOM_SOURCE": "snyk",
		})
		if _, err := LoadConfig(); err == nil {
			t.Error("expected error for unsupported SBOM_SOURCE")
		}
	})
	t.Run("bad format", func(t *testing.T) {
		setEnv(t, map[string]string{
			"S3_BUCKET":   "test-bucket",
			"REPOSITORY":  "owner/repo",
			"SBOM_FORMAT": "swidtag",
		})
		if _, err := LoadConfig(); err == nil {
			t.Error("expected error for unsupported SBOM_FORMAT")
		}
	})
}

func TestLoadConfig_SanitizesMendUUIDLists(t *testing.T) {
	setEnv(t, map[string]string{
		"S3_BUCKET":          "test-bucket",
		"SBOM_SOURCE":        "mend",
		"MEND_EMAIL":         "user@example.com",
		"MEND_ORG_UUID":      "11111111-1111-1111-1111-111111111111",
		"MEND_USER_KEY":      "key",
		"MEND_PROJECT_UUID":  "22222222-2222-2222-2222-222222222222",
		"MEND_PROJECT_UUIDS": "22222222-2222-2222-2222-222222222222, 33333333-3333-3333-3333-333333333333",
	})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := "22222222-2222-2222-2222-222222222222,33333333-3333-3333-3333-333333333333"
	if cfg.MendProjectUUIDs != want {
		t.Errorf("MendProjectUUIDs = %q, want %q", cfg.MendProjectUUIDs, want)
	}
}

func TestLoadConfig_RejectsInvalidUUIDInList(t *testing.T) {
	setEnv(t, map[string]string{
		"S3_BUCKET":          "test-bucket",
		"SBOM_SOURCE":        "mend",
		"MEND_EMAIL":         "user@example.com",
		"MEND_ORG_UUID":      "11111111-1111-1111-1111-111111111111",
		"MEND_USER_KEY":      "key",
		"MEND_PROJECT_UUID":  "22222222-2222-2222-2222-222222222222",
		"MEND_PROJECT_UUIDS": "22222222-2222-2222-2222-222222222222,not-a-uuid",
	})
	if _, err := LoadConfig(); err == nil {
		t.Error("expected error for invalid UUID in list")
	}
}

func TestLoadConfig_ClickHouseDatabaseSanitized(t *testing.T) {
	setEnv(t, map[string]string{
		"S3_BUCKET":           "test-bucket",
		"REPOSITORY":          "owner/repo",
		"CLICKHOUSE_URL":      "http://localhost:8123/",
		"CLICKHOUSE_DATABASE": "ana-lytics.dev",
		"CLICKHOUSE_USERNAME": "default",
	})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ClickHouseDatabase != "analyticsdev" {
		t.Errorf("ClickHouseDatabase = %q, want %q", cfg.ClickHouseDatabase, "analyticsdev")
	}
}

func TestLoadConfig_RedactsViaLengthCap(t *testing.T) {
	long := repeatStr("a", 2000)
	setEnv(t, map[string]string{
		"S3_BUCKET":    "test-bucket",
		"REPOSITORY":   "owner/repo",
		"GITHUB_TOKEN": long,
	})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.GitHubToken) > 1000 {
		t.Errorf("GitHub token not capped: %d chars", len(cfg.GitHubToken))
	}
}

func TestLoadConfig_RejectsInjectionInRepository(t *testing.T) {
	setEnv(t, map[string]string{
		"S3_BUCKET":  "test-bucket",
		"REPOSITORY": "owner/repo`whoami`",
	})
	cfg, err := LoadConfig()
	if err != nil {
		// Either it errors out (because the result of stripping isn't owner/repo)
		// or it succeeds with the dangerous chars stripped — both are acceptable
		// parity outcomes. We just need to confirm no backticks survive.
		_ = err
		return
	}
	if containsAny(cfg.Repository, "`$();|&<>") {
		t.Errorf("Repository contains dangerous chars: %q", cfg.Repository)
	}
}

func repeatStr(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func containsAny(s, chars string) bool {
	for _, c := range chars {
		for _, r := range s {
			if r == c {
				return true
			}
		}
	}
	return false
}

func TestLoadConfig_SlackWebhookURL(t *testing.T) {
	const good = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

	t.Run("absent leaves the field empty", func(t *testing.T) {
		setEnv(t, map[string]string{
			"S3_BUCKET":  "test-bucket",
			"REPOSITORY": "owner/repo",
		})
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.SlackWebhookURL != "" {
			t.Errorf("SlackWebhookURL = %q, want empty", cfg.SlackWebhookURL)
		}
	})

	t.Run("valid webhook is kept", func(t *testing.T) {
		setEnv(t, map[string]string{
			"S3_BUCKET":         "test-bucket",
			"REPOSITORY":        "owner/repo",
			"SLACK_WEBHOOK_URL": " " + good + "\n",
		})
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.SlackWebhookURL != good {
			t.Errorf("SlackWebhookURL = %q, want %q", cfg.SlackWebhookURL, good)
		}
	})

	t.Run("non-Slack host is rejected without echoing the value", func(t *testing.T) {
		const marker = "SECRETMARKER123"
		setEnv(t, map[string]string{
			"S3_BUCKET":         "test-bucket",
			"REPOSITORY":        "owner/repo",
			"SLACK_WEBHOOK_URL": "https://evil.example/services/" + marker,
		})
		_, err := LoadConfig()
		if err == nil {
			t.Fatal("LoadConfig accepted a non-Slack webhook host")
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("error %q echoes the webhook URL", err.Error())
		}
	})
}

func TestSecretsFromEnv(t *testing.T) {
	setEnv(t, map[string]string{"S3_BUCKET": "public-bucket"})
	if got := SecretsFromEnv(); len(got) != 0 {
		t.Fatalf("SecretsFromEnv() with no sensitive env = %q, want none", got)
	}
	setEnv(t, map[string]string{
		"MEND_PROJECT_UUIDS": " a1 ,, b2 ",
		"GITHUB_TOKEN":       "tok",
		"AWS_SESSION_TOKEN":  "sess",
		"S3_BUCKET":          "public-bucket",
	})
	got := SecretsFromEnv()
	sort.Strings(got)
	// The list variable contributes the whole value and each entry.
	want := []string{"a1", "a1 ,, b2", "b2", "sess", "tok"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SecretsFromEnv() = %q, want %q", got, want)
	}

	// Other variables are never split: a comma inside a password is part of it.
	setEnv(t, map[string]string{"CLICKHOUSE_PASSWORD": "p,w"})
	if got := SecretsFromEnv(); !reflect.DeepEqual(got, []string{"p,w"}) {
		t.Errorf("SecretsFromEnv() with a comma in a password = %q, want [p,w]", got)
	}
}

func TestConfigSecrets(t *testing.T) {
	setEnv(t, map[string]string{
		"CLICKHOUSE_URL":    "https://raw.example.com:8443/",
		"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
	})
	cfg := &Config{
		GitHubToken: "tok", MendEmail: "m@example.com", MendOrgUUID: "org", MendUserKey: "ukey",
		MendProjectUUID: "proj", MendProductUUID: "prod", MendOrgScopeUUID: "scope", MendProjectUUIDs: "u1, u2,",
		WizAuthEndpoint: "https://auth.wiz.example", WizAPIEndpoint: "https://api.wiz.example",
		WizClientID: "cid", WizClientSecret: "csec", WizReportID: "rep",
		TrivyECRExternalID: "ext", ClickHouseURL: "https://raw.example.com:8443", ClickHousePassword: "pw",
		SlackWebhookURL: "https://hooks.slack.com/services/T/B/X",
		// Non-sensitive inputs must never be redacted, or the message becomes useless.
		S3Bucket: "bucket", S3Key: "key.json", Repository: "o/r", ClickHouseDatabase: "db", ClickHouseUsername: "user", TrivyImage: "img:1",
	}
	got := cfg.Secrets()
	set := map[string]bool{}
	for _, v := range got {
		if v == "" || v != strings.TrimSpace(v) {
			t.Errorf("Secrets() contains an empty or untrimmed value %q", v)
		}
		set[v] = true
	}
	for _, want := range []string{
		"tok", "m@example.com", "org", "ukey", "proj", "prod", "scope", "u1", "u2",
		"https://auth.wiz.example", "https://api.wiz.example", "cid", "csec", "rep", "ext",
		"https://raw.example.com:8443", "pw", "https://hooks.slack.com/services/T/B/X",
		// raw environment values, including the untrimmed URL
		"https://raw.example.com:8443/", "AKIAEXAMPLE",
		// the basic-auth spelling of the ClickHouse credentials
		base64.StdEncoding.EncodeToString([]byte("user:pw")),
	} {
		if !set[want] {
			t.Errorf("Secrets() is missing %q", want)
		}
	}
	for _, public := range []string{"bucket", "key.json", "o/r", "db", "user", "img:1"} {
		if set[public] {
			t.Errorf("Secrets() wrongly contains non-sensitive value %q", public)
		}
	}
	if got := (&Config{}).Secrets(); len(got) != 2 {
		t.Errorf("empty Config with two sensitive env vars: Secrets() = %q, want exactly the env values", got)
	}
}

func TestSlackWebhookURLFromEnv(t *testing.T) {
	setEnv(t, map[string]string{})
	if _, err := SlackWebhookURLFromEnv(); err == nil {
		t.Error("expected an error when SLACK_WEBHOOK_URL is unset")
	}
	setEnv(t, map[string]string{"SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/X "})
	got, err := SlackWebhookURLFromEnv()
	if err != nil || got != "https://hooks.slack.com/services/T/B/X" {
		t.Errorf("SlackWebhookURLFromEnv() = %q, %v", got, err)
	}
	setEnv(t, map[string]string{"SLACK_WEBHOOK_URL": "https://evil.example/services/SECRETMARKER"})
	if _, err := SlackWebhookURLFromEnv(); err == nil || strings.Contains(err.Error(), "SECRETMARKER") {
		t.Errorf("invalid webhook: err = %v, want an error that withholds the value", err)
	}
}

func TestSensitiveEnvVars_ReturnsACopy(t *testing.T) {
	got := SensitiveEnvVars()
	for _, want := range []string{"SLACK_WEBHOOK_URL", "CLICKHOUSE_URL", "MEND_PROJECT_UUIDS", "AWS_SESSION_TOKEN"} {
		if !slices.Contains(got, want) {
			t.Errorf("SensitiveEnvVars() lacks %q", want)
		}
	}
	got[0] = "MUTATED"
	if slices.Contains(SensitiveEnvVars(), "MUTATED") {
		t.Error("SensitiveEnvVars() must return a copy, not the package slice")
	}
}
