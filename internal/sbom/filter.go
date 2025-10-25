// Package sbom provides functionalities for filtering files for SBOM generation.
package sbom

import (
	"path/filepath"
	"strings"

	"github.com/ClickHouse/ClickBOM/pkg/logger"
)

// FileFilter defines inclusion and exclusion patterns for filtering files.
type FileFilter struct {
	Include []string
	Exclude []string
}

// NewFileFilter creates a new FileFilter with the given include and exclude patterns.
func NewFileFilter(include, exclude string) *FileFilter {
	return &FileFilter{
		Include: parsePatterns(include),
		Exclude: parsePatterns(exclude),
	}
}

func parsePatterns(patterns string) []string {
	if patterns == "" {
		return nil
	}

	parts := strings.Split(patterns, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// MatchesPattern checks if the filename matches any of the provided patterns.
func (f *FileFilter) MatchesPattern(filename string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}

	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, filename)
		if err != nil {
			logger.Warning("Invalid pattern %s: %v", pattern, err)
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// ShouldInclude determines if a file should be included based on the filter rules.
func (f *FileFilter) ShouldInclude(filename string) bool {
	// If include patterns specified, file must match at least one
	if len(f.Include) > 0 {
		if !f.MatchesPattern(filename, f.Include) {
			return false
		}
	}

	// If exclude patterns specified and file matches, exclude it
	if len(f.Exclude) > 0 {
		if f.MatchesPattern(filename, f.Exclude) {
			return false
		}
	}

	return true
}

// FilterFiles filters the given list of files based on the FileFilter rules.
func (f *FileFilter) FilterFiles(files []string) []string {
	var filtered []string

	for _, file := range files {
		filename := filepath.Base(file)
		if f.ShouldInclude(filename) {
			filtered = append(filtered, file)
		} else {
			logger.Debug("Filtered out: %s", filename)
		}
	}

	logger.Info("Filtered %d files to %d files", len(files), len(filtered))
	return filtered
}
