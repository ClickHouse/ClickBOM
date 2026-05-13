package sbom

import "testing"

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		msg  string
		want bool
	}{
		{"Request timed out", true},
		{"Server-side: Request timed out, please retry", true},
		{"Failed to generate SBOM", true},
		{"upstream timeout reached", true},
		{"Not Found", false},
		{"Bad credentials", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.msg, func(t *testing.T) {
			if got := isRetryableError(tc.msg); got != tc.want {
				t.Errorf("isRetryableError(%q) = %v, want %v", tc.msg, got, tc.want)
			}
		})
	}
}

func TestRetryableGitHubMessage(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantMsg     string
		wantRetry   bool
		wantPresent bool
	}{
		{
			name:        "transient message triggers retry",
			body:        `{"message": "Request timed out"}`,
			wantMsg:     "Request timed out",
			wantRetry:   true,
			wantPresent: true,
		},
		{
			name:        "non-transient message detected but not retryable",
			body:        `{"message": "Not Found"}`,
			wantMsg:     "Not Found",
			wantRetry:   false,
			wantPresent: true,
		},
		{
			name:        "valid SBOM JSON has no .message",
			body:        `{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
			wantPresent: false,
		},
		{
			name:        "non-JSON body",
			body:        `<html>not json</html>`,
			wantPresent: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg, retry := retryableGitHubMessage([]byte(tc.body))
			if tc.wantPresent {
				if msg != tc.wantMsg {
					t.Errorf("msg = %q, want %q", msg, tc.wantMsg)
				}
				if retry != tc.wantRetry {
					t.Errorf("retry = %v, want %v", retry, tc.wantRetry)
				}
			} else if msg != "" || retry {
				t.Errorf("expected (empty, false), got (%q, %v)", msg, retry)
			}
		})
	}
}
