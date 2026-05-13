package storage

import (
	"testing"
)

func TestTSVEscape(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain ascii untouched", in: "MIT", want: "MIT"},
		{name: "tab escaped", in: "a\tb", want: `a\tb`},
		{name: "newline escaped", in: "line1\nline2", want: `line1\nline2`},
		{name: "carriage return escaped", in: "a\rb", want: `a\rb`},
		{name: "backslash doubled", in: `a\b`, want: `a\\b`},
		{name: "null byte escaped", in: "a\x00b", want: `a\0b`},
		{name: "no-escape fast path keeps unicode", in: "café", want: "café"},
		{name: "mixed", in: "a\tb\\c\nd", want: `a\tb\\c\nd`},
		{name: "empty", in: "", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tsvEscape(tc.in); got != tc.want {
				t.Errorf("tsvEscape(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name string
		comp map[string]interface{}
		want string
	}{
		{"CycloneDX version field", map[string]interface{}{"version": "1.2.3"}, "1.2.3"},
		{"SPDX versionInfo field", map[string]interface{}{"versionInfo": "4.5.6"}, "4.5.6"},
		{"version wins over versionInfo when both set",
			map[string]interface{}{"version": "1.0", "versionInfo": "9.9"}, "1.0"},
		{"empty version falls back to versionInfo",
			map[string]interface{}{"version": "", "versionInfo": "9.9"}, "9.9"},
		{"neither field present", map[string]interface{}{"name": "x"}, "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractVersion(tc.comp); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractLicense(t *testing.T) {
	tests := []struct {
		name string
		comp map[string]interface{}
		want string
	}{
		{
			name: "CycloneDX licenses[].license.id",
			comp: map[string]interface{}{
				"licenses": []interface{}{
					map[string]interface{}{"license": map[string]interface{}{"id": "MIT"}},
				},
			},
			want: "MIT",
		},
		{
			name: "CycloneDX licenses[].license.name (no id)",
			comp: map[string]interface{}{
				"licenses": []interface{}{
					map[string]interface{}{"license": map[string]interface{}{"name": "Apache License 2.0"}},
				},
			},
			want: "Apache License 2.0",
		},
		{
			name: "CycloneDX licenses[].license.expression (no id/name)",
			comp: map[string]interface{}{
				"licenses": []interface{}{
					map[string]interface{}{"license": map[string]interface{}{"expression": "MIT OR Apache-2.0"}},
				},
			},
			want: "MIT OR Apache-2.0",
		},
		{
			name: "CycloneDX licenses[] flattened (id directly on entry)",
			comp: map[string]interface{}{
				"licenses": []interface{}{
					map[string]interface{}{"id": "BSD-3-Clause"},
				},
			},
			want: "BSD-3-Clause",
		},
		{
			name: "CycloneDX properties spdx:license-concluded",
			comp: map[string]interface{}{
				"properties": []interface{}{
					map[string]interface{}{"name": "spdx:license-concluded", "value": "GPL-3.0"},
				},
			},
			want: "GPL-3.0",
		},
		{
			name: "CycloneDX properties spdx:license-declared",
			comp: map[string]interface{}{
				"properties": []interface{}{
					map[string]interface{}{"name": "unrelated:thing", "value": "noise"},
					map[string]interface{}{"name": "spdx:license-declared", "value": "ISC"},
				},
			},
			want: "ISC",
		},
		{
			name: "SPDX licenseConcluded",
			comp: map[string]interface{}{"licenseConcluded": "MIT"},
			want: "MIT",
		},
		{
			name: "SPDX licenseDeclared (no concluded)",
			comp: map[string]interface{}{"licenseDeclared": "Apache-2.0"},
			want: "Apache-2.0",
		},
		{
			name: "Concluded wins over declared",
			comp: map[string]interface{}{"licenseConcluded": "MIT", "licenseDeclared": "Apache-2.0"},
			want: "MIT",
		},
		{
			name: "Nothing extractable",
			comp: map[string]interface{}{"name": "x"},
			want: "unknown",
		},
		{
			name: "Empty licenses array falls through",
			comp: map[string]interface{}{
				"licenses":         []interface{}{},
				"licenseConcluded": "MIT",
			},
			want: "MIT",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractLicense(tc.comp); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
