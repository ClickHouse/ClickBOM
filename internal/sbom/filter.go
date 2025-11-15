// Package sbom provides pattern matching for filtering files.
package sbom

import (
	"path/filepath"
	"strings"

	"github.com/ClickHouse/ClickBOM/pkg/logger"
)

// MatchesPattern checks if a filename matches any pattern in a comma-separated list.
func MatchesPattern(filename, patterns string) bool {
	if patterns == "" {
		return false
	}

	// Split patterns by comma
	patternList := strings.Split(patterns, ",")

	for _, pattern := range patternList {
		// Trim whitespace
		pattern = strings.TrimSpace(pattern)

		if pattern == "" {
			continue
		}

		// Use filepath.Match for wildcard matching
		matched, err := filepath.Match(pattern, filename)
		if err != nil {
			logger.Warning("Invalid pattern %s: %v", pattern, err)
			continue
		}

		if matched {
			logger.Debug("File %s matches pattern %s", filename, pattern)
			return true
		}
	}

	return false
}

// ShouldIncludeFile determines if a file should be included based on include/exclude patterns.
func ShouldIncludeFile(filename, includePatterns, excludePatterns string) bool {
	// If include patterns are specified, file must match at least one
	if includePatterns != "" {
		if !MatchesPattern(filename, includePatterns) {
			logger.Debug("File %s does not match include patterns", filename)
			return false
		}
	}

	// If exclude patterns are specified, file must not match any
	if excludePatterns != "" {
		if MatchesPattern(filename, excludePatterns) {
			logger.Debug("File %s matches exclude patterns", filename)
			return false
		}
	}

	return true
}
