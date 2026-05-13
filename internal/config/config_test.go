package config

import (
	"os"
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
