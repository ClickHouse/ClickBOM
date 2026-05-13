package sbom

import "testing"

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		patterns string
		want     bool
	}{
		{name: "empty patterns", filename: "a.json", patterns: "", want: false},
		{name: "exact match", filename: "main.json", patterns: "main.json", want: true},
		{name: "wildcard match", filename: "prod-app.json", patterns: "prod-*.json", want: true},
		{name: "wildcard no match", filename: "main.json", patterns: "prod-*.json", want: false},
		{name: "multiple comma-separated patterns - first matches", filename: "a.json", patterns: "a.json,b.json", want: true},
		{name: "multiple comma-separated patterns - second matches", filename: "b.json", patterns: "a.json,b.json", want: true},
		{name: "multiple patterns - none match", filename: "c.json", patterns: "a.json,b.json", want: false},
		{name: "whitespace trimmed", filename: "a.json", patterns: "  a.json  , b.json", want: true},
		{name: "empty pattern entries skipped", filename: "a.json", patterns: ",,a.json,,", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchesPattern(tc.filename, tc.patterns); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestShouldIncludeFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		include  string
		exclude  string
		want     bool
	}{
		{name: "no filters - included", filename: "a.json", include: "", exclude: "", want: true},
		{name: "include matches", filename: "prod-a.json", include: "prod-*.json", want: true},
		{name: "include excludes non-matching", filename: "test-a.json", include: "prod-*.json", want: false},
		{name: "exclude only - matching excluded", filename: "test-a.json", exclude: "test-*.json", want: false},
		{name: "exclude only - non-matching kept", filename: "main.json", exclude: "test-*.json", want: true},
		{name: "both - included and not excluded", filename: "prod-a.json", include: "prod-*.json", exclude: "test-*.json", want: true},
		{name: "both - included but also excluded -> exclude wins", filename: "prod-test.json", include: "prod-*.json", exclude: "*-test.json", want: false},
		{name: "both - not included", filename: "other.json", include: "prod-*.json", exclude: "*-test.json", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldIncludeFile(tc.filename, tc.include, tc.exclude); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
