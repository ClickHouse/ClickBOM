package sbom

import (
	"encoding/json"
	"os"

	"github.com/ClickHouse/ClickBOM/pkg/logger"
)

// LicenseMapper handles mapping of unknown licenses to known licenses
type LicenseMapper struct {
	mappings map[string]string
}

// NewLicenseMapper creates a new license mapper from a JSON file
func NewLicenseMapper(mappingFile string) (*LicenseMapper, error) {
	data, err := os.ReadFile(mappingFile)
	if err != nil {
		return nil, err
	}

	var mappings map[string]string
	if err := json.Unmarshal(data, &mappings); err != nil {
		return nil, err
	}

	logger.Debug("Loaded %d license mappings", len(mappings))

	return &LicenseMapper{
		mappings: mappings,
	}, nil
}

// MapLicense maps an unknown license to a known one, or returns the original
func (m *LicenseMapper) MapLicense(componentName, license string) string {
	// If license is already known, return it
	if license != "" && license != "unknown" && license != "null" { // nolint:goconst
		return license
	}

	// Try to find a mapping for this component
	if mapped, exists := m.mappings[componentName]; exists {
		logger.Debug("Mapped license for %s: unknown -> %s", componentName, mapped)
		return mapped
	}

	// No mapping found, return unknown
	return "unknown"
}

// MapComponent maps the license for a component (modifies in place)
func (m *LicenseMapper) MapComponent(comp map[string]interface{}) {
	name, _ := comp["name"].(string)
	license, _ := comp["license"].(string)

	if name != "" {
		mappedLicense := m.MapLicense(name, license)
		comp["license"] = mappedLicense
	}
}

// MapComponents maps licenses for multiple components
func (m *LicenseMapper) MapComponents(components []map[string]interface{}) {
	for _, comp := range components {
		m.MapComponent(comp)
	}
}

// GetMapping returns the mapping for a specific component, if it exists
func (m *LicenseMapper) GetMapping(componentName string) (string, bool) {
	license, exists := m.mappings[componentName]
	return license, exists
}

// HasMapping checks if a mapping exists for a component
func (m *LicenseMapper) HasMapping(componentName string) bool {
	_, exists := m.mappings[componentName]
	return exists
}
