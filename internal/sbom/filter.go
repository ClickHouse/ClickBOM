package sbom

import (
    "path/filepath"
    "strings"
    
    "github.com/ClickHouse/ClickBOM/pkg/logger"
)

type FileFilter struct {
    Include []string
    Exclude []string
}

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
