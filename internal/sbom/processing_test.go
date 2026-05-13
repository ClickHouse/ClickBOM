package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeTestFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestDetectSBOMFormat(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    Format
	}{
		{
			name:    "CycloneDX with bomFormat",
			content: `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`,
			want:    FormatCycloneDX,
		},
		{
			name:    "CycloneDX without bomFormat but with metadata.component",
			content: `{"specVersion":"1.5","metadata":{"component":{"type":"application","name":"x"}}}`,
			want:    FormatCycloneDX,
		},
		{
			name:    "SPDX with spdxVersion",
			content: `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"x"}`,
			want:    FormatSPDXJSON,
		},
		{
			name:    "SPDX without spdxVersion but with SPDXID",
			content: `{"SPDXID":"SPDXRef-DOCUMENT","name":"x"}`,
			want:    FormatSPDXJSON,
		},
		{
			name:    "Unrelated JSON object",
			content: `{"hello":"world"}`,
			want:    FormatUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestFile(t, "sbom.json", tc.content)
			got, err := DetectSBOMFormat(path)
			if err != nil {
				t.Fatalf("DetectSBOMFormat: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractSBOMFromWrapper(t *testing.T) {
	t.Run("wrapped SBOM unwraps the sbom field", func(t *testing.T) {
		in := writeTestFile(t, "in.json", `{"sbom":{"bomFormat":"CycloneDX","specVersion":"1.6"}}`)
		out := writeTestFile(t, "out.json", "")
		if err := ExtractSBOMFromWrapper(in, out); err != nil {
			t.Fatalf("unwrap: %v", err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("read out: %v", err)
		}
		var doc struct {
			BOMFormat string `json:"bomFormat"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if doc.BOMFormat != "CycloneDX" {
			t.Errorf("bomFormat = %q, want CycloneDX", doc.BOMFormat)
		}
	})

	t.Run("unwrapped SBOM is copied through", func(t *testing.T) {
		content := `{"bomFormat":"CycloneDX","specVersion":"1.6"}`
		in := writeTestFile(t, "in.json", content)
		out := writeTestFile(t, "out.json", "")
		if err := ExtractSBOMFromWrapper(in, out); err != nil {
			t.Fatalf("copy: %v", err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(data) != content {
			t.Errorf("got %q, want %q", string(data), content)
		}
	})

	t.Run("invalid JSON errors", func(t *testing.T) {
		in := writeTestFile(t, "in.json", "not json")
		out := writeTestFile(t, "out.json", "")
		if err := ExtractSBOMFromWrapper(in, out); err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestFixSPDXCompatibility(t *testing.T) {
	in := `{
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {"name": "a", "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl"}]},
            {"name": "b", "externalRefs": [{"referenceCategory": "SECURITY"}]},
            {"name": "c", "externalRefs": [{"referenceCategory": "WHATEVER"}]},
            {"name": "d", "externalRefs": [{"referenceCategory": "PERSISTENT_ID"}]}
        ]
    }`
	inPath := writeTestFile(t, "in.json", in)
	outPath := filepath.Join(t.TempDir(), "out.json")

	if err := FixSPDXCompatibility(inPath, outPath); err != nil {
		t.Fatalf("FixSPDXCompatibility: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	var doc struct {
		Packages []struct {
			Name         string `json:"name"`
			ExternalRefs []struct {
				ReferenceCategory string `json:"referenceCategory"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := map[string]string{
		"a": "PACKAGE_MANAGER",
		"b": "SECURITY",
		"c": "OTHER",
		"d": "PERSISTENT_ID",
	}
	for _, pkg := range doc.Packages {
		gotCat := pkg.ExternalRefs[0].ReferenceCategory
		if gotCat != want[pkg.Name] {
			t.Errorf("package %s: got %s, want %s", pkg.Name, gotCat, want[pkg.Name])
		}
	}
}

func BenchmarkDetectSBOMFormat(b *testing.B) {
	// Create test SBOM file
	testFile := "/tmp/bench-sbom.json"
	testContent := []byte(`{
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": []
    }`)
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}
	defer func() {
		if err := os.Remove(testFile); err != nil {
			b.Fatalf("Failed to remove test file: %v", err)
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DetectSBOMFormat(testFile)
		if err != nil {
			b.Fatalf("DetectSBOMFormat failed: %v", err)
		}
	}
}
