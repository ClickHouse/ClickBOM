//go:build integration

package sbom

import (
	"testing"
)

func TestLicenseMapperWithRealFile(t *testing.T) {
	// Test with the actual license-mappings.json file
	mapper, err := NewLicenseMapper("../../license-mappings.json")
	if err != nil {
		t.Fatalf("Failed to load real license mappings: %v", err)
	}

	// Test some known mappings
	tests := []struct {
		component string
		want      string
	}{
		{"4d63.com/gocheckcompilerdirectives", "MIT"},
		{"actions/cache", "MIT"},
		{"CycloneDX/gh-gomod-generate-sbom", "Apache-2.0"},
	}

	for _, tt := range tests {
		t.Run(tt.component, func(t *testing.T) {
			got := mapper.MapLicense(tt.component, "unknown")
			if got != tt.want {
				t.Errorf("MapLicense(%s) = %v, want %v", tt.component, got, tt.want)
			}
		})
	}
}
