package main

import (
	"reflect"
	"testing"

	"github.com/ClickHouse/ClickBOM/internal/config"
)

func TestGenerateTableName(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{
			name: "merge mode strips .json and appends _merged",
			cfg:  &config.Config{Merge: true, S3Key: "clickbom.json"},
			want: "clickbom_merged",
		},
		{
			name: "merge mode lowercases and sanitizes",
			cfg:  &config.Config{Merge: true, S3Key: "Path/To/My-File.json"},
			want: "path_to_my_file_merged",
		},
		{
			name: "merge mode without extension still appends _merged",
			cfg:  &config.Config{Merge: true, S3Key: "rolling"},
			want: "rolling_merged",
		},
		{
			name: "github lowercases repository",
			cfg:  &config.Config{SBOMSource: "github", Repository: "ClickHouse/ClickBOM"},
			want: "clickhouse_clickbom",
		},
		{
			name: "mend prefers project UUID",
			cfg: &config.Config{
				SBOMSource:      "mend",
				MendProjectUUID: "abc-123",
				MendProductUUID: "should-not-be-used",
			},
			want: "mend_abc_123",
		},
		{
			name: "mend falls back to product UUID",
			cfg:  &config.Config{SBOMSource: "mend", MendProductUUID: "prod-uuid"},
			want: "mend_prod_uuid",
		},
		{
			name: "wiz lowercases report id",
			cfg:  &config.Config{SBOMSource: "wiz", WizReportID: "ReportXYZ-1"},
			want: "wiz_reportxyz_1",
		},
		{
			name: "trivy uses basename of image, sanitized",
			cfg:  &config.Config{SBOMSource: "trivy", TrivyImage: "registry.example.com/app:1.2.3"},
			want: "trivy_app_1_2_3",
		},
		{
			name: "unknown source returns sbom_data",
			cfg:  &config.Config{SBOMSource: "novel"},
			want: "sbom_data",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := generateTableName(tc.cfg); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSelectMergeCandidates(t *testing.T) {
	tests := []struct {
		name string
		keys []string
		cfg  *config.Config
		want []string
	}{
		{
			name: "skip output target and non-json",
			keys: []string{
				"a.json", "b.json", "clickbom.json", "README.md", "subdir/",
			},
			cfg:  &config.Config{S3Key: "clickbom.json"},
			want: []string{"a.json", "b.json"},
		},
		{
			name: "target with prefix path also matches by basename",
			keys: []string{"reports/clickbom.json", "reports/keep.json"},
			cfg:  &config.Config{S3Key: "clickbom.json"},
			want: []string{"reports/keep.json"},
		},
		{
			name: "include filter limits the set",
			keys: []string{"prod-a.json", "test-b.json", "prod-c.json"},
			cfg:  &config.Config{S3Key: "out.json", Include: "prod-*.json"},
			want: []string{"prod-a.json", "prod-c.json"},
		},
		{
			name: "exclude trims survivors",
			keys: []string{"a.json", "b-test.json", "c.json"},
			cfg:  &config.Config{S3Key: "out.json", Exclude: "*-test.json"},
			want: []string{"a.json", "c.json"},
		},
		{
			name: "case-insensitive .json suffix",
			keys: []string{"file.JSON", "file.json", "image.png"},
			cfg:  &config.Config{S3Key: "out.json"},
			want: []string{"file.JSON", "file.json"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := selectMergeCandidates(tc.keys, tc.cfg)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDefaultSourceForConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{
			name: "github with repo",
			cfg:  &config.Config{SBOMSource: "github", Repository: "ClickHouse/ClickBOM"},
			want: "ClickHouse/ClickBOM",
		},
		{
			name: "github with empty repo falls through to bare source name",
			cfg:  &config.Config{SBOMSource: "github"},
			want: "github",
		},
		{
			name: "mend prefers project UUID",
			cfg: &config.Config{
				SBOMSource:       "mend",
				MendProjectUUID:  "11111111-1111-1111-1111-111111111111",
				MendProductUUID:  "22222222-2222-2222-2222-222222222222",
				MendOrgScopeUUID: "33333333-3333-3333-3333-333333333333",
			},
			want: "mend:11111111-1111-1111-1111-111111111111",
		},
		{
			name: "mend falls back to product UUID",
			cfg: &config.Config{
				SBOMSource:       "mend",
				MendProductUUID:  "22222222-2222-2222-2222-222222222222",
				MendOrgScopeUUID: "33333333-3333-3333-3333-333333333333",
			},
			want: "mend:22222222-2222-2222-2222-222222222222",
		},
		{
			name: "mend falls back to org-scope UUID",
			cfg: &config.Config{
				SBOMSource:       "mend",
				MendOrgScopeUUID: "33333333-3333-3333-3333-333333333333",
			},
			want: "mend:33333333-3333-3333-3333-333333333333",
		},
		{
			name: "mend with no UUIDs returns mend:unknown",
			cfg:  &config.Config{SBOMSource: "mend"},
			want: "mend:unknown",
		},
		{
			name: "wiz with report ID",
			cfg:  &config.Config{SBOMSource: "wiz", WizReportID: "rep-123"},
			want: "wiz:rep-123",
		},
		{
			name: "trivy with image",
			cfg:  &config.Config{SBOMSource: "trivy", TrivyImage: "registry/app:1.2.3"},
			want: "trivy:registry/app:1.2.3",
		},
		{
			name: "unknown source falls through to itself",
			cfg:  &config.Config{SBOMSource: "novel-source"},
			want: "novel-source",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultSourceForConfig(tc.cfg); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
