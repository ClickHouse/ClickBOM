package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeMergeTestFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestCollectComponentsWithSource(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		sourceRef string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "adds source to each component",
			content:   `{"components":[{"name":"a","version":"1"},{"name":"b","version":"2"}]}`,
			sourceRef: "src",
			wantCount: 2,
		},
		{
			name:      "no components field returns empty",
			content:   `{"bomFormat":"CycloneDX"}`,
			sourceRef: "src",
			wantCount: 0,
		},
		{
			name:      "empty components array returns empty",
			content:   `{"components":[]}`,
			sourceRef: "src",
			wantCount: 0,
		},
		{
			name:      "overwrites existing source field",
			content:   `{"components":[{"name":"a","source":"OLD"}]}`,
			sourceRef: "NEW",
			wantCount: 1,
		},
		{
			name:    "invalid JSON returns error",
			content: "{this is not json",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeMergeTestFile(t, tc.content)
			got, err := CollectComponentsWithSource(path, tc.sourceRef)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if len(got) != tc.wantCount {
				t.Errorf("got %d components, want %d", len(got), tc.wantCount)
			}
			for _, c := range got {
				if c["source"] != tc.sourceRef {
					t.Errorf("component source = %v, want %q", c["source"], tc.sourceRef)
				}
			}
		})
	}
}

func TestCollectComponentsWithSource_MissingFile(t *testing.T) {
	if _, err := CollectComponentsWithSource("/nonexistent/file.json", "src"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestDeduplicateComponents(t *testing.T) {
	in := []map[string]interface{}{
		{"name": "a", "version": "1", "purl": "pkg:x/a@1", "source": "S1"},
		{"name": "a", "version": "1", "purl": "pkg:x/a@1", "source": "S1"}, // exact duplicate -> dropped
		{"name": "a", "version": "1", "purl": "pkg:x/a@1", "source": "S2"}, // different source -> kept
		{"name": "a", "version": "2", "purl": "pkg:x/a@2", "source": "S1"}, // different version -> kept
		{"name": "b"}, // missing fields -> treated as unknown
	}
	got := DeduplicateComponents(in)
	if len(got) != 4 {
		t.Errorf("got %d, want 4 unique components", len(got))
	}
}

func TestMergeSBOMs_RoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	a := filepath.Join(tempDir, "a.json")
	b := filepath.Join(tempDir, "b.json")
	if err := os.WriteFile(a, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"alpha"}},"components":[{"name":"libA","version":"1"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"beta"}},"components":[{"name":"libB","version":"2"},{"name":"libA","version":"1"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(tempDir, "merged.json")
	if err := MergeSBOMs([]string{a, b}, out); err != nil {
		t.Fatalf("MergeSBOMs: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read merged: %v", err)
	}
	var doc struct {
		BOMFormat   string                   `json:"bomFormat"`
		SpecVersion string                   `json:"specVersion"`
		Components  []map[string]interface{} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal merged: %v", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", doc.BOMFormat)
	}
	if doc.SpecVersion != "1.6" {
		t.Errorf("specVersion = %q, want 1.6", doc.SpecVersion)
	}
	// Two unique by name+version+purl+source because libA appears with the
	// same fields under both sources (alpha and beta) so both are kept.
	if len(doc.Components) < 2 {
		t.Errorf("got %d components, want >= 2", len(doc.Components))
	}
	// Each component must carry a source field.
	for _, c := range doc.Components {
		if _, ok := c["source"].(string); !ok {
			t.Errorf("component missing source field: %v", c)
		}
	}
}

func TestExtractSourceReference(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name: "Strategy 1 - spdx:document:name property",
			content: `{
				"metadata": {
					"properties": [
						{"name": "noise", "value": "x"},
						{"name": "spdx:document:name", "value": "github.com/Org/Repo"}
					]
				}
			}`,
			want: "github.com/Org/Repo",
		},
		{
			name: "Strategy 2 - metadata.component.name",
			content: `{
				"metadata": {"component": {"name": "wiz-app"}}
			}`,
			want: "wiz-app",
		},
		{
			name: "Strategy 3 - metadata.component.bom-ref when name missing",
			content: `{
				"metadata": {"component": {"bom-ref": "pkg:generic/x"}}
			}`,
			want: "pkg:generic/x",
		},
		{
			name:    "Strategy 4 - top-level name",
			content: `{"name": "top-level-name"}`,
			want:    "top-level-name",
		},
		{
			name: "Strategy 5 - non-generator tool name wins over filename",
			content: `{
				"metadata": {
					"tools": [
						{"name": "CycloneDX"},
						{"name": "cyclonedx-merge"},
						{"name": "Trivy"}
					]
				}
			}`,
			want: "Trivy",
		},
		{
			name: "Strategy 5 - all tools are generators, falls through to filename",
			content: `{
				"metadata": {
					"tools": [
						{"name": "CycloneDX"},
						{"name": "GitHub.com-Dependency"},
						{"name": "protobom"}
					]
				}
			}`,
			want: "fallback",
		},
		{
			name:    "Strategy 6 - filename without extension",
			content: `{"unrelated": "doc"}`,
			want:    "fallback",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fallback.json")
			if err := os.WriteFile(path, []byte(tc.content), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, err := ExtractSourceReference(path)
			if err != nil {
				t.Fatalf("ExtractSourceReference: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFirstNonGeneratorToolName(t *testing.T) {
	tests := []struct {
		name  string
		tools interface{}
		want  string
	}{
		{
			name:  "nil tools",
			tools: nil,
			want:  "",
		},
		{
			name: "all generators",
			tools: []interface{}{
				map[string]interface{}{"name": "CycloneDX"},
				map[string]interface{}{"name": "protobom"},
			},
			want: "",
		},
		{
			name: "first non-generator wins",
			tools: []interface{}{
				map[string]interface{}{"name": "CycloneDX"},
				map[string]interface{}{"name": "Trivy"},
				map[string]interface{}{"name": "Syft"},
			},
			want: "Trivy",
		},
		{
			name: "tools without name field are skipped",
			tools: []interface{}{
				map[string]interface{}{"vendor": "Anchore"},
				map[string]interface{}{"name": "Syft"},
			},
			want: "Syft",
		},
		{
			name:  "tools is a map (CDX 1.5+ shape) - returns empty per bash parity",
			tools: map[string]interface{}{"components": []interface{}{}},
			want:  "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstNonGeneratorToolName(tc.tools); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
