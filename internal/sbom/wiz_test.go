package sbom

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"
)

func TestHasZipAndGzipMagic(t *testing.T) {
	zipBuf := []byte{0x50, 0x4B, 0x03, 0x04}
	gzBuf := []byte{0x1F, 0x8B, 0x08, 0x00}
	rawJSON := []byte(`{"a":1}`)

	if !hasZipMagic(zipBuf) {
		t.Error("zipBuf should be detected as ZIP")
	}
	if hasZipMagic(gzBuf) || hasZipMagic(rawJSON) {
		t.Error("non-ZIP buffers misdetected as ZIP")
	}
	if !hasGzipMagic(gzBuf) {
		t.Error("gzBuf should be detected as gzip")
	}
	if hasGzipMagic(zipBuf) || hasGzipMagic(rawJSON) {
		t.Error("non-gzip buffers misdetected as gzip")
	}
}

func TestNormalizeWizPayload_PassthroughJSON(t *testing.T) {
	in := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	out, err := normalizeWizPayload(in, t.TempDir())
	if err != nil {
		t.Fatalf("normalizeWizPayload: %v", err)
	}
	if !bytes.Equal(in, out) {
		t.Errorf("got %q, want passthrough %q", out, in)
	}
}

func TestNormalizeWizPayload_Gzip(t *testing.T) {
	payload := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)
	var gzBuf bytes.Buffer
	w := gzip.NewWriter(&gzBuf)
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	out, err := normalizeWizPayload(gzBuf.Bytes(), t.TempDir())
	if err != nil {
		t.Fatalf("normalizeWizPayload: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Errorf("decoded gzip mismatch: got %q want %q", out, payload)
	}
}

func makeZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip Create: %v", err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestNormalizeWizPayload_SingleJSONInZip(t *testing.T) {
	payload := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`
	zipBytes := makeZip(t, map[string]string{
		"report.json": payload,
		"README.txt":  "noise",
	})

	out, err := normalizeWizPayload(zipBytes, t.TempDir())
	if err != nil {
		t.Fatalf("normalizeWizPayload: %v", err)
	}
	if string(out) != payload {
		t.Errorf("got %q, want %q", string(out), payload)
	}
}

func TestNormalizeWizPayload_MultipleJSONInZipMerged(t *testing.T) {
	a := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"alpha"}},"components":[{"name":"libA","version":"1"}]}`
	b := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"beta"}},"components":[{"name":"libB","version":"2"}]}`
	zipBytes := makeZip(t, map[string]string{
		"a.json": a,
		"b.json": b,
	})

	out, err := normalizeWizPayload(zipBytes, t.TempDir())
	if err != nil {
		t.Fatalf("normalizeWizPayload: %v", err)
	}
	var merged struct {
		BOMFormat  string                   `json:"bomFormat"`
		Components []map[string]interface{} `json:"components"`
	}
	if err := json.Unmarshal(out, &merged); err != nil {
		t.Fatalf("unmarshal merged: %v", err)
	}
	if merged.BOMFormat != "CycloneDX" {
		t.Errorf("merged bomFormat = %q, want CycloneDX", merged.BOMFormat)
	}
	if len(merged.Components) != 2 {
		t.Errorf("merged components = %d, want 2", len(merged.Components))
	}
}

func TestNormalizeWizPayload_EmptyZipErrors(t *testing.T) {
	zipBytes := makeZip(t, map[string]string{"README.txt": "no sbom here"})
	_, err := normalizeWizPayload(zipBytes, t.TempDir())
	if err == nil {
		t.Error("expected error when ZIP has no .json entries")
	}
}
