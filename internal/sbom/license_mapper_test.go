package sbom

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewLicenseMapper(t *testing.T) {
	// Create temp mapping file
	tempDir := t.TempDir()
	mappingFile := filepath.Join(tempDir, "test-mappings.json")

	mappingContent := `{
        "4d63.com/gocheckcompilerdirectives": "MIT",
        "actions/cache": "MIT",
        "test-component": "Apache-2.0"
    }`

	if err := os.WriteFile(mappingFile, []byte(mappingContent), 0644); err != nil {
		t.Fatalf("Failed to create test mapping file: %v", err)
	}

	mapper, err := NewLicenseMapper(mappingFile)
	if err != nil {
		t.Fatalf("NewLicenseMapper() error = %v", err)
	}

	if mapper == nil {
		t.Fatal("Expected mapper, got nil")
	}

	if len(mapper.mappings) != 3 {
		t.Errorf("Expected 3 mappings, got %d", len(mapper.mappings))
	}
}

func TestNewLicenseMapper_FileNotFound(t *testing.T) {
	_, err := NewLicenseMapper("/nonexistent/file.json")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

func TestNewLicenseMapper_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	mappingFile := filepath.Join(tempDir, "invalid.json")

	if err := os.WriteFile(mappingFile, []byte("not valid json"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err := NewLicenseMapper(mappingFile)
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

func TestMapLicense(t *testing.T) {
	mapper := &LicenseMapper{
		mappings: map[string]string{
			"test-component":    "MIT",
			"another-component": "Apache-2.0",
		},
	}

	tests := []struct {
		name          string
		componentName string
		license       string
		want          string
	}{
		{
			name:          "known license - keep it",
			componentName: "any-component",
			license:       "BSD-3-Clause",
			want:          "BSD-3-Clause",
		},
		{
			name:          "unknown license with mapping",
			componentName: "test-component",
			license:       "unknown",
			want:          "MIT",
		},
		{
			name:          "empty license with mapping",
			componentName: "test-component",
			license:       "",
			want:          "MIT",
		},
		{
			name:          "null license with mapping",
			componentName: "test-component",
			license:       "null",
			want:          "MIT",
		},
		{
			name:          "unknown license without mapping",
			componentName: "unmapped-component",
			license:       "unknown",
			want:          "unknown",
		},
		{
			name:          "different component with mapping",
			componentName: "another-component",
			license:       "",
			want:          "Apache-2.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapper.MapLicense(tt.componentName, tt.license)
			if got != tt.want {
				t.Errorf("MapLicense() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapComponent(t *testing.T) {
	mapper := &LicenseMapper{
		mappings: map[string]string{
			"test-component": "MIT",
		},
	}

	comp := map[string]interface{}{
		"name":    "test-component",
		"version": "1.0.0",
		"license": "unknown",
	}

	mapper.MapComponent(comp)

	if comp["license"] != "MIT" {
		t.Errorf("Expected license to be mapped to MIT, got %v", comp["license"])
	}
}

func TestMapComponents(t *testing.T) {
	mapper := &LicenseMapper{
		mappings: map[string]string{
			"component-a": "MIT",
			"component-b": "Apache-2.0",
		},
	}

	components := []map[string]interface{}{
		{
			"name":    "component-a",
			"license": "unknown",
		},
		{
			"name":    "component-b",
			"license": "",
		},
		{
			"name":    "component-c",
			"license": "BSD-3-Clause",
		},
	}

	mapper.MapComponents(components)

	// Check first component
	if components[0]["license"] != "MIT" {
		t.Errorf("Component A: expected MIT, got %v", components[0]["license"])
	}

	// Check second component
	if components[1]["license"] != "Apache-2.0" {
		t.Errorf("Component B: expected Apache-2.0, got %v", components[1]["license"])
	}

	// Check third component (should remain unchanged)
	if components[2]["license"] != "BSD-3-Clause" {
		t.Errorf("Component C: expected BSD-3-Clause, got %v", components[2]["license"])
	}
}

func TestGetMapping(t *testing.T) {
	mapper := &LicenseMapper{
		mappings: map[string]string{
			"test-component": "MIT",
		},
	}

	t.Run("existing mapping", func(t *testing.T) {
		license, exists := mapper.GetMapping("test-component")
		if !exists {
			t.Error("Expected mapping to exist")
		}
		if license != "MIT" {
			t.Errorf("Expected MIT, got %v", license)
		}
	})

	t.Run("non-existing mapping", func(t *testing.T) {
		_, exists := mapper.GetMapping("nonexistent")
		if exists {
			t.Error("Expected mapping to not exist")
		}
	})
}

func TestHasMapping(t *testing.T) {
	mapper := &LicenseMapper{
		mappings: map[string]string{
			"test-component": "MIT",
		},
	}

	if !mapper.HasMapping("test-component") {
		t.Error("Expected HasMapping to return true for test-component")
	}

	if mapper.HasMapping("nonexistent") {
		t.Error("Expected HasMapping to return false for nonexistent")
	}
}
