package sbom

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/ClickBOM/internal/config"
)

func newTestMendClient(project, product, orgScope, projectUUIDs string) *MendClient {
	return NewMendClient(&config.Config{
		MendEmail:        "sbom@example.com",
		MendOrgUUID:      "00000000-0000-0000-0000-00000000aaaa",
		MendUserKey:      "key",
		MendBaseURL:      "https://api-saas.mend.io",
		MendProjectUUID:  project,
		MendProductUUID:  product,
		MendOrgScopeUUID: orgScope,
		MendProjectUUIDs: projectUUIDs,
		MendMaxWaitTime:  60,
		MendPollInterval: 10,
	})
}

func TestExportRequest_ProjectScope(t *testing.T) {
	m := newTestMendClient("11111111-1111-1111-1111-111111111111", "", "", "")

	url, payload, err := m.exportRequest()
	if err != nil {
		t.Fatalf("exportRequest: %v", err)
	}
	if want := "https://api-saas.mend.io/api/v3.0/projects/11111111-1111-1111-1111-111111111111/dependencies/reports/SBOM"; url != want {
		t.Errorf("url = %q, want %q", url, want)
	}
	if payload["scopeType"] != "project" || payload["scopeUuid"] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("payload scope = %v/%v, want project scope", payload["scopeType"], payload["scopeUuid"])
	}
	if _, ok := payload["projectUuids"]; ok {
		t.Error("project scope must not send projectUuids")
	}
	if payload["reportType"] != "cycloneDX_1_5" || payload["format"] != "json" {
		t.Errorf("unexpected report type/format: %v/%v", payload["reportType"], payload["format"])
	}
}

func TestExportRequest_ProjectTakesPrecedenceOverProduct(t *testing.T) {
	m := newTestMendClient("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333", "")

	url, _, err := m.exportRequest()
	if err != nil {
		t.Fatalf("exportRequest: %v", err)
	}
	if !strings.Contains(url, "/projects/11111111-1111-1111-1111-111111111111/") {
		t.Errorf("expected project endpoint, got %q", url)
	}
}

func TestExportRequest_ProductScopeWithProjectUUIDs(t *testing.T) {
	m := newTestMendClient("", "22222222-2222-2222-2222-222222222222", "", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb,")

	url, payload, err := m.exportRequest()
	if err != nil {
		t.Fatalf("exportRequest: %v", err)
	}
	if want := "https://api-saas.mend.io/api/v3.0/applications/22222222-2222-2222-2222-222222222222/dependencies/reports/SBOM"; url != want {
		t.Errorf("url = %q, want %q", url, want)
	}
	wantUUIDs := []string{"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}
	if got, _ := payload["projectUuids"].([]string); !reflect.DeepEqual(got, wantUUIDs) {
		t.Errorf("projectUuids = %v, want %v", payload["projectUuids"], wantUUIDs)
	}
	if v, ok := payload["maxDepthLevel"]; ok {
		t.Errorf("maxDepthLevel must not be sent (Mend only accepts 1..4 and we rely on its default), got %v", v)
	}
	if _, ok := payload["scopeType"]; ok {
		t.Error("application-scope endpoint takes the scope from the URL, not the body")
	}
}

func TestExportRequest_ProductScopeWithoutProjectUUIDsOmitsField(t *testing.T) {
	m := newTestMendClient("", "22222222-2222-2222-2222-222222222222", "", "")

	_, payload, err := m.exportRequest()
	if err != nil {
		t.Fatalf("exportRequest: %v", err)
	}
	if v, ok := payload["projectUuids"]; ok {
		t.Errorf("projectUuids must be omitted when MEND_PROJECT_UUIDS is unset, got %v", v)
	}
}

func TestExportRequest_OrgScopeIsRejected(t *testing.T) {
	m := newTestMendClient("", "", "33333333-3333-3333-3333-333333333333", "")

	url, payload, err := m.exportRequest()
	if err == nil {
		t.Fatalf("expected an error for organization scope, got url=%q payload=%v", url, payload)
	}
	if !strings.Contains(err.Error(), "MEND_PRODUCT_UUID") {
		t.Errorf("error should point at the supported scopes, got: %v", err)
	}
}

func TestExportRequest_NoScopeErrors(t *testing.T) {
	m := newTestMendClient("", "", "", "")

	url, payload, err := m.exportRequest()
	if err == nil {
		t.Fatalf("expected error, got url=%q payload=%v", url, payload)
	}
	if url != "" {
		t.Errorf("url must be empty on error, got %q", url)
	}
}

func TestSplitUUIDList(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty", in: "", want: nil},
		{name: "whitespace only", in: "  ", want: nil},
		{name: "single", in: "a", want: []string{"a"}},
		{name: "trims and drops empties", in: " a, ,b,,c ", want: []string{"a", "b", "c"}},
		{name: "trailing comma", in: "a,b,", want: []string{"a", "b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := splitUUIDList(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("splitUUIDList(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckReportStatus_Non200IsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/reports/report-1") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer jwt-1" {
			t.Errorf("Authorization = %q, want Bearer jwt-1", got)
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
	}))
	defer srv.Close()

	m := newTestMendClient("11111111-1111-1111-1111-111111111111", "", "", "")
	m.baseURL = srv.URL
	m.jwtToken = "jwt-1"
	m.httpClient = &http.Client{Timeout: 5 * time.Second}

	status, err := m.checkReportStatus(t.Context(), "report-1")
	if err == nil {
		t.Fatalf("expected error for HTTP 401, got status %q", status)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention the HTTP status, got: %v", err)
	}
}

func TestCheckReportStatus_ReturnsStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"status":"IN_PROGRESS"}}`))
	}))
	defer srv.Close()

	m := newTestMendClient("11111111-1111-1111-1111-111111111111", "", "", "")
	m.baseURL = srv.URL
	m.jwtToken = "jwt-1"
	m.httpClient = &http.Client{Timeout: 5 * time.Second}

	status, err := m.checkReportStatus(t.Context(), "report-1")
	if err != nil {
		t.Fatalf("checkReportStatus: %v", err)
	}
	if status != "IN_PROGRESS" {
		t.Errorf("status = %q, want IN_PROGRESS", status)
	}
}
