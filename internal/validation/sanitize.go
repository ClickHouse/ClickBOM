package validation

import (
    "fmt"
    "regexp"
    "strings"
    "unicode"
)

var (
    repoRegex   = regexp.MustCompile(`^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$`)
    emailRegex  = regexp.MustCompile(`^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    s3BucketRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
    uuidRegex   = regexp.MustCompile(`^[0-9a-fA-F]{8}-?([0-9a-fA-F]{4}-?){3}[0-9a-fA-F]{12}$`)
    httpURLRegex = regexp.MustCompile(`^https?://[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]+)?/?$`)
)

func SanitizeString(input string, maxLength int) string {
    // Remove null bytes and control characters
    var result strings.Builder
    for _, r := range input {
        if r == 0 || r < 32 || r == 127 {
            continue
        }
        if r > 127 {
            continue
        }
        // Remove dangerous characters
        if strings.ContainsRune("$(){}|;&<>`@[]", r) {
            continue
        }
        result.WriteRune(r)
    }
    
    sanitized := result.String()
    if len(sanitized) > maxLength {
        return sanitized[:maxLength]
    }
    return sanitized
}

func SanitizeRepository(repo string) (string, error) {
    sanitized := removeChars(repo, `[^a-zA-Z0-9._/-]`)
    
    if !repoRegex.MatchString(sanitized) {
        return "", fmt.Errorf("invalid repository format: %s (must be 'owner/repo')", repo)
    }
    
    return sanitized, nil
}

func SanitizeEmail(email string) (string, error) {
    // Remove control characters and newlines
    sanitized := strings.TrimSpace(email)
    sanitized = strings.ReplaceAll(sanitized, "\n", "")
    sanitized = strings.ReplaceAll(sanitized, "\r", "")
    sanitized = strings.ReplaceAll(sanitized, "\t", "")
    
    // Remove dangerous characters but keep email-valid ones
    sanitized = removeChars(sanitized, `[^a-zA-Z0-9@._+-]`)
    
    if !emailRegex.MatchString(sanitized) {
        return "", fmt.Errorf("invalid email format: %s", email)
    }
    
    return sanitized, nil
}

func SanitizeS3Bucket(bucket string) (string, error) {
    // Convert to lowercase
    sanitized := strings.ToLower(bucket)
    
    // Remove invalid characters
    sanitized = removeChars(sanitized, `[^a-z0-9.-]`)
    
    if !s3BucketRegex.MatchString(sanitized) {
        return "", fmt.Errorf("invalid S3 bucket name: %s", bucket)
    }
    
    // Check for IP-like format
    if regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(sanitized) {
        return "", fmt.Errorf("S3 bucket name cannot be IP address format: %s", bucket)
    }
    
    return sanitized, nil
}

func SanitizeS3Key(key string) (string, error) {
    // Remove dangerous characters
    sanitized := removeChars(key, `[^a-zA-Z0-9._/-]`)
    
    // Remove path traversal
    sanitized = strings.ReplaceAll(sanitized, "..", "")
    
    // Remove multiple slashes
    for strings.Contains(sanitized, "//") {
        sanitized = strings.ReplaceAll(sanitized, "//", "/")
    }
    
    // Remove leading/trailing slashes
    sanitized = strings.Trim(sanitized, "/")
    
    if sanitized == "" {
        return "", fmt.Errorf("invalid S3 key: cannot be empty")
    }
    
    return sanitized, nil
}

func SanitizeURL(url, urlType string) (string, error) {
    // Remove control characters
    sanitized := removeControlChars(url)
    
    var valid bool
    switch urlType {
    case "mend", "wiz":
        // Must be HTTPS
        valid = strings.HasPrefix(sanitized, "https://") && 
                regexp.MustCompile(`^https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$`).MatchString(sanitized)
    case "clickhouse":
        valid = httpURLRegex.MatchString(sanitized)
    default:
        valid = httpURLRegex.MatchString(sanitized)
    }
    
    if !valid {
        return "", fmt.Errorf("invalid %s URL format: %s", urlType, url)
    }
    
    return sanitized, nil
}

func SanitizeUUID(uuid, fieldName string) (string, error) {
    sanitized := removeChars(uuid, `[^a-fA-F0-9-]`)
    
    if !uuidRegex.MatchString(sanitized) {
        return "", fmt.Errorf("invalid UUID format for %s: %s", fieldName, uuid)
    }
    
    return sanitized, nil
}

func SanitizeNumeric(value string, fieldName string, min, max int) (int, error) {
    sanitized := removeChars(value, `[^0-9]`)
    
    if sanitized == "" {
        return 0, fmt.Errorf("invalid numeric value for %s: %s", fieldName, value)
    }
    
    var num int
    _, err := fmt.Sscanf(sanitized, "%d", &num)
    if err != nil {
        return 0, fmt.Errorf("invalid numeric value for %s: %s", fieldName, value)
    }
    
    if num < min || num > max {
        return 0, fmt.Errorf("numeric value for %s out of range (%d-%d): %d", fieldName, min, max, num)
    }
    
    return num, nil
}

func SanitizePatterns(patterns string) string {
    if patterns == "" {
        return ""
    }
    
    parts := strings.Split(patterns, ",")
    var sanitized []string
    
    for _, pattern := range parts {
        pattern = strings.TrimSpace(pattern)
        pattern = removeChars(pattern, `[^a-zA-Z0-9.*_-]`)
        if pattern != "" {
            sanitized = append(sanitized, pattern)
        }
    }
    
    return strings.Join(sanitized, ",")
}

func removeChars(s, pattern string) string {
    re := regexp.MustCompile(pattern)
    return re.ReplaceAllString(s, "")
}

func removeControlChars(s string) string {
    var result strings.Builder
    for _, r := range s {
        if !unicode.IsControl(r) {
            result.WriteRune(r)
        }
    }
    return result.String()
}
