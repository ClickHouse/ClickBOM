package validation

import (
	"strings"
	"testing"
)

func repeat(s string, n int) string { return strings.Repeat(s, n) }

func TestSanitizeRepository(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "valid repository",
			input:   "owner/repo",
			want:    "owner/repo",
			wantErr: false,
		},
		{
			name:    "repository with hyphens",
			input:   "my-org/my-repo",
			want:    "my-org/my-repo",
			wantErr: false,
		},
		{
			name:    "repository with dots",
			input:   "my.org/repo.name",
			want:    "my.org/repo.name",
			wantErr: false,
		},
		{
			name:    "removes dangerous characters",
			input:   "owner$bad/repo;rm",
			want:    "ownerbad/reporm",
			wantErr: false,
		},
		{
			name:    "invalid - no slash",
			input:   "invalidrepo",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid - empty owner",
			input:   "/repo",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeRepository(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("SanitizeRepository() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("SanitizeRepository() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeEmail(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "valid email",
			input:   "user@example.com",
			want:    "user@example.com",
			wantErr: false,
		},
		{
			name:    "email with plus",
			input:   "user+tag@example.com",
			want:    "user+tag@example.com",
			wantErr: false,
		},
		{
			name:    "removes newlines",
			input:   "user@example.com\n",
			want:    "user@example.com",
			wantErr: false,
		},
		{
			name:    "invalid - no @",
			input:   "invalid-email",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid - no domain",
			input:   "user@",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeEmail(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("SanitizeEmail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("SanitizeEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		maxLength int
		want      string
	}{
		{
			name:      "removes dangerous characters",
			input:     "test$command`echo hello`",
			maxLength: 1000,
			want:      "testcommandecho hello",
		},
		{
			name:      "respects length limit",
			input:     "abcdefghijklmnopqrstuvwxyz",
			maxLength: 10,
			want:      "abcdefghij",
		},
		{
			name:      "removes control characters",
			input:     "test\x00\x01\x02string",
			maxLength: 1000,
			want:      "teststring",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeString(tt.input, tt.maxLength)
			if got != tt.want {
				t.Errorf("SanitizeString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeUUIDList(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "empty", input: "", want: "", wantErr: false},
		{
			name:  "single uuid",
			input: "11111111-1111-1111-1111-111111111111",
			want:  "11111111-1111-1111-1111-111111111111",
		},
		{
			name:  "multiple uuids with whitespace",
			input: "11111111-1111-1111-1111-111111111111, 22222222-2222-2222-2222-222222222222",
			want:  "11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222",
		},
		{
			name:    "rejects invalid uuid in the middle",
			input:   "11111111-1111-1111-1111-111111111111,not-a-uuid",
			wantErr: true,
		},
		{
			name:  "skips empty entries from trailing commas",
			input: "11111111-1111-1111-1111-111111111111,,",
			want:  "11111111-1111-1111-1111-111111111111",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizeUUIDList(tc.input, "MEND_PROJECT_UUIDS")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSanitizeDatabaseName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "plain name", input: "analytics", want: "analytics"},
		{name: "drops punctuation", input: "ana-lytics.dev", want: "analyticsdev"},
		{name: "prepends underscore on leading digit", input: "2024_db", want: "_2024_db"},
		{name: "all-invalid -> empty", input: "---", want: ""},
		{name: "preserves underscores", input: "a_b_c", want: "a_b_c"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizeDatabaseName(tc.input); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		kind    string
		want    string
		wantErr bool
	}{
		{name: "http general", url: "http://example.com", kind: "general", want: "http://example.com"},
		{name: "https general", url: "https://example.com", kind: "general", want: "https://example.com"},
		{name: "clickhouse http", url: "http://ch.example.com:8123/", kind: "clickhouse", want: "http://ch.example.com:8123/"},
		{name: "mend requires https", url: "http://api.mend.io", kind: "mend", wantErr: true},
		{name: "mend accepts https", url: "https://api.mend.io", kind: "mend", want: "https://api.mend.io"},
		{name: "wiz requires https", url: "http://api.wiz.io", kind: "wiz", wantErr: true},
		{name: "rejects ftp", url: "ftp://example.com", kind: "general", wantErr: true},
		{name: "rejects javascript scheme", url: "javascript:alert(1)", kind: "general", wantErr: true},
		{name: "rejects data scheme", url: "data:text/html,<script>", kind: "general", wantErr: true},
		{name: "rejects file scheme", url: "file:///etc/passwd", kind: "general", wantErr: true},
		{name: "rejects missing protocol", url: "example.com", kind: "general", wantErr: true},
		{name: "rejects double protocol", url: "https://https://example.com", kind: "general", wantErr: true},
		{name: "strips control characters", url: "https://example.com\x00", kind: "general", want: "https://example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizeURL(tc.url, tc.kind)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSanitizeS3Bucket(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "valid", input: "my-bucket", want: "my-bucket"},
		{name: "lowercased", input: "My-Bucket", want: "my-bucket"},
		{name: "dots accepted", input: "my.bucket.name", want: "my.bucket.name"},
		{name: "removes invalid chars", input: "my$bucket!", want: "mybucket"},
		{name: "rejects too short", input: "ab", wantErr: true},
		{name: "rejects too long", input: "a" + repeat("b", 63), wantErr: true},
		{name: "rejects ip-like", input: "10.0.0.1", wantErr: true},
		{name: "rejects leading dash", input: "-bucket", wantErr: true},
		{name: "rejects trailing dash", input: "bucket-", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizeS3Bucket(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSanitizeS3Key(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "plain key", input: "sboms/main.json", want: "sboms/main.json"},
		{name: "removes dangerous chars", input: "sboms/x$y;z.json", want: "sboms/xyz.json"},
		{name: "removes path traversal", input: "../etc/passwd", want: "etc/passwd"},
		{name: "collapses multiple slashes", input: "a//b///c.json", want: "a/b/c.json"},
		{name: "strips leading slash", input: "/key.json", want: "key.json"},
		{name: "strips trailing slash", input: "key.json/", want: "key.json"},
		{name: "rejects all-invalid", input: "$$$", wantErr: true},
		{name: "rejects empty", input: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizeS3Key(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSanitizeUUID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "canonical UUID", input: "12345678-1234-1234-1234-123456789012", want: "12345678-1234-1234-1234-123456789012"},
		{name: "no hyphens accepted", input: "12345678123412341234123456789012", want: "12345678123412341234123456789012"},
		{name: "uppercase accepted", input: "ABCDEF12-3456-7890-ABCD-EF1234567890", want: "ABCDEF12-3456-7890-ABCD-EF1234567890"},
		{name: "removes invalid chars then validates", input: "12345678-1234-1234-1234-12345678901z", wantErr: true},
		{name: "too short", input: "1234-5678", wantErr: true},
		{name: "non-hex rejected", input: "ggggggg-gggg-gggg-gggg-gggggggggggg", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizeUUID(tc.input, "FIELD")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSanitizeNumeric(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		min     int
		max     int
		want    int
		wantErr bool
	}{
		{name: "valid in range", value: "60", min: 0, max: 100, want: 60},
		{name: "lower bound", value: "0", min: 0, max: 100, want: 0},
		{name: "upper bound", value: "100", min: 0, max: 100, want: 100},
		{name: "strips non-numeric", value: "30s", min: 0, max: 100, want: 30},
		{name: "leading zeros normalized", value: "007", min: 0, max: 100, want: 7},
		{name: "empty rejected", value: "", min: 0, max: 100, wantErr: true},
		{name: "all-non-numeric rejected", value: "abc", min: 0, max: 100, wantErr: true},
		{name: "below min", value: "5", min: 10, max: 100, wantErr: true},
		{name: "above max", value: "150", min: 0, max: 100, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizeNumeric(tc.value, "FIELD", tc.min, tc.max)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSanitizePatterns(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty input", input: "", want: ""},
		{name: "single pattern", input: "*.json", want: "*.json"},
		{name: "trims whitespace", input: " a.json , b.json ", want: "a.json,b.json"},
		{name: "removes dangerous chars", input: "a$.json,b;.json", want: "a.json,b.json"},
		{name: "preserves wildcards", input: "*-prod.json,prod-*.json", want: "*-prod.json,prod-*.json"},
		{name: "drops empty entries from only commas", input: ",,,", want: ""},
		{name: "drops mid-empty entries", input: "a.json,,b.json", want: "a.json,b.json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizePatterns(tc.input); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSanitizeStringInjectionVectors(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
		maxLen int
	}{
		{name: "backticks stripped", input: "value`whoami`", want: "valuewhoami", maxLen: 100},
		{name: "dollar-paren stripped", input: "value$(whoami)", want: "valuewhoami", maxLen: 100},
		{name: "pipe stripped", input: "a|b", want: "ab", maxLen: 100},
		{name: "semicolon stripped", input: "a;b", want: "ab", maxLen: 100},
		{name: "ampersand stripped", input: "a&b", want: "ab", maxLen: 100},
		{name: "redirection stripped", input: "a>b<c", want: "abc", maxLen: 100},
		{name: "null byte stripped", input: "a\x00b", want: "ab", maxLen: 100},
		{name: "empty string", input: "", want: "", maxLen: 100},
		{name: "all dangerous chars -> empty", input: "$(){};|&<>`@[]", want: "", maxLen: 100},
		{name: "respects max length", input: "abcdefghij", want: "abcd", maxLen: 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizeString(tc.input, tc.maxLen); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSanitizeBool(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		defaultVal bool
		want       bool
		wantErr    bool
	}{
		{name: "empty uses default true", value: "", defaultVal: true, want: true},
		{name: "empty uses default false", value: "", defaultVal: false, want: false},
		{name: "explicit true", value: "true", want: true},
		{name: "explicit false", value: "false", want: false},
		{name: "True (mixed case) rejected", value: "True", wantErr: true},
		{name: "yes rejected", value: "yes", wantErr: true},
		{name: "1 rejected", value: "1", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizeBool(tc.value, "FIELD", tc.defaultVal)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
