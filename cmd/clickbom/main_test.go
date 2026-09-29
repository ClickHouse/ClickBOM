package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/ClickBOM/internal/config"
	"github.com/ClickHouse/ClickBOM/internal/notify"
)

func TestGenerateTableName(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{
			name: "merge mode strips .json and appends _merged",
			cfg:  &config.Config{Merge: true, S3Key: "clickbom.json"},
			want: "clickbom_merged",
		},
		{
			name: "merge mode lowercases and sanitizes",
			cfg:  &config.Config{Merge: true, S3Key: "Path/To/My-File.json"},
			want: "path_to_my_file_merged",
		},
		{
			name: "merge mode without extension still appends _merged",
			cfg:  &config.Config{Merge: true, S3Key: "rolling"},
			want: "rolling_merged",
		},
		{
			name: "github lowercases repository",
			cfg:  &config.Config{SBOMSource: "github", Repository: "ClickHouse/ClickBOM"},
			want: "clickhouse_clickbom",
		},
		{
			name: "mend prefers project UUID",
			cfg: &config.Config{
				SBOMSource:      "mend",
				MendProjectUUID: "abc-123",
				MendProductUUID: "should-not-be-used",
			},
			want: "mend_abc_123",
		},
		{
			name: "mend falls back to product UUID",
			cfg:  &config.Config{SBOMSource: "mend", MendProductUUID: "prod-uuid"},
			want: "mend_prod_uuid",
		},
		{
			name: "wiz lowercases report id",
			cfg:  &config.Config{SBOMSource: "wiz", WizReportID: "ReportXYZ-1"},
			want: "wiz_reportxyz_1",
		},
		{
			name: "trivy uses basename of image, sanitized",
			cfg:  &config.Config{SBOMSource: "trivy", TrivyImage: "registry.example.com/app:1.2.3"},
			want: "trivy_app_1_2_3",
		},
		{
			name: "unknown source returns sbom_data",
			cfg:  &config.Config{SBOMSource: "novel"},
			want: "sbom_data",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := generateTableName(tc.cfg); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSelectMergeCandidates(t *testing.T) {
	tests := []struct {
		name string
		keys []string
		cfg  *config.Config
		want []string
	}{
		{
			name: "skip output target and non-json",
			keys: []string{
				"a.json", "b.json", "clickbom.json", "README.md", "subdir/",
			},
			cfg:  &config.Config{S3Key: "clickbom.json"},
			want: []string{"a.json", "b.json"},
		},
		{
			name: "target with prefix path also matches by basename",
			keys: []string{"reports/clickbom.json", "reports/keep.json"},
			cfg:  &config.Config{S3Key: "clickbom.json"},
			want: []string{"reports/keep.json"},
		},
		{
			name: "include filter limits the set",
			keys: []string{"prod-a.json", "test-b.json", "prod-c.json"},
			cfg:  &config.Config{S3Key: "out.json", Include: "prod-*.json"},
			want: []string{"prod-a.json", "prod-c.json"},
		},
		{
			name: "exclude trims survivors",
			keys: []string{"a.json", "b-test.json", "c.json"},
			cfg:  &config.Config{S3Key: "out.json", Exclude: "*-test.json"},
			want: []string{"a.json", "c.json"},
		},
		{
			name: "case-insensitive .json suffix",
			keys: []string{"file.JSON", "file.json", "image.png"},
			cfg:  &config.Config{S3Key: "out.json"},
			want: []string{"file.JSON", "file.json"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := selectMergeCandidates(tc.keys, tc.cfg)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDefaultSourceForConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{
			name: "github with repo",
			cfg:  &config.Config{SBOMSource: "github", Repository: "ClickHouse/ClickBOM"},
			want: "ClickHouse/ClickBOM",
		},
		{
			name: "github with empty repo falls through to bare source name",
			cfg:  &config.Config{SBOMSource: "github"},
			want: "github",
		},
		{
			name: "mend prefers project UUID",
			cfg: &config.Config{
				SBOMSource:       "mend",
				MendProjectUUID:  "11111111-1111-1111-1111-111111111111",
				MendProductUUID:  "22222222-2222-2222-2222-222222222222",
				MendOrgScopeUUID: "33333333-3333-3333-3333-333333333333",
			},
			want: "mend:11111111-1111-1111-1111-111111111111",
		},
		{
			name: "mend falls back to product UUID",
			cfg: &config.Config{
				SBOMSource:       "mend",
				MendProductUUID:  "22222222-2222-2222-2222-222222222222",
				MendOrgScopeUUID: "33333333-3333-3333-3333-333333333333",
			},
			want: "mend:22222222-2222-2222-2222-222222222222",
		},
		{
			name: "mend falls back to org-scope UUID",
			cfg: &config.Config{
				SBOMSource:       "mend",
				MendOrgScopeUUID: "33333333-3333-3333-3333-333333333333",
			},
			want: "mend:33333333-3333-3333-3333-333333333333",
		},
		{
			name: "mend with no UUIDs returns mend:unknown",
			cfg:  &config.Config{SBOMSource: "mend"},
			want: "mend:unknown",
		},
		{
			name: "wiz with report ID",
			cfg:  &config.Config{SBOMSource: "wiz", WizReportID: "rep-123"},
			want: "wiz:rep-123",
		},
		{
			name: "trivy with image",
			cfg:  &config.Config{SBOMSource: "trivy", TrivyImage: "registry/app:1.2.3"},
			want: "trivy:registry/app:1.2.3",
		},
		{
			name: "unknown source falls through to itself",
			cfg:  &config.Config{SBOMSource: "novel-source"},
			want: "novel-source",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultSourceForConfig(tc.cfg); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// sensitiveConfig fills every field the README marks Sensitive with a
// recognisable marker so tests can prove none of them reach the Slack summary.
func sensitiveConfig(source string) *config.Config {
	return &config.Config{
		SBOMSource:         source,
		SBOMFormat:         "cyclonedx",
		S3Bucket:           "my-sbom-bucket",
		S3Key:              "out/clickbom.json",
		Repository:         "ClickHouse/ClickBOM",
		TrivyImage:         "registry.example.com/app:1.2.3",
		GitHubToken:        "SECRET_github_token",
		MendEmail:          "SECRET_mend@example.com",
		MendOrgUUID:        "SECRET-org-uuid",
		MendUserKey:        "SECRET_mend_user_key",
		MendProjectUUID:    "SECRET-project-uuid",
		MendProductUUID:    "SECRET-product-uuid",
		MendOrgScopeUUID:   "SECRET-org-scope-uuid",
		MendProjectUUIDs:   "SECRET-uuid-a,SECRET-uuid-b",
		WizAuthEndpoint:    "https://SECRET-auth.wiz.io/oauth/token",
		WizAPIEndpoint:     "https://SECRET-api.wiz.io",
		WizClientID:        "SECRET_wiz_client_id",
		WizClientSecret:    "SECRET_wiz_client_secret",
		WizReportID:        "SECRET-wiz-report",
		TrivyECRExternalID: "SECRET_external_id",
		AWSAccessKeyID:     "SECRET_AKIA",
		AWSSecretAccessKey: "SECRET_aws_secret",
		ClickHouseURL:      "https://SECRET-ch.example.com:8443",
		ClickHouseDatabase: "sboms",
		ClickHouseUsername: "clickbom",
		ClickHousePassword: "SECRET_ch_password",
		SlackWebhookURL:    "https://hooks.slack.com/services/SECRET/SECRET/SECRET",
	}
}

func with(c *config.Config, mutate func(*config.Config)) *config.Config {
	mutate(c)
	return c
}

func TestBuildSummary(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want []string // Source, Target, Format, Bucket, Key, ClickHouse
	}{
		{
			name: "github names the repository and the table",
			cfg:  sensitiveConfig("github"),
			want: []string{"github", "ClickHouse/ClickBOM", "cyclonedx", "my-sbom-bucket", "out/clickbom.json", "sboms.clickhouse_clickbom"},
		},
		{
			name: "mend project scope hides the UUID and the table",
			cfg:  sensitiveConfig("mend"),
			want: []string{"mend", "project scope", "cyclonedx", "my-sbom-bucket", "out/clickbom.json", "sboms"},
		},
		{
			name: "mend product scope",
			cfg:  with(sensitiveConfig("mend"), func(c *config.Config) { c.MendProjectUUID = "" }),
			want: []string{"mend", "product scope", "cyclonedx", "my-sbom-bucket", "out/clickbom.json", "sboms"},
		},
		{
			name: "wiz hides the report id and the table",
			cfg:  sensitiveConfig("wiz"),
			want: []string{"wiz", "report", "cyclonedx", "my-sbom-bucket", "out/clickbom.json", "sboms"},
		},
		{
			name: "trivy names the image and the table",
			cfg:  sensitiveConfig("trivy"),
			want: []string{"trivy", "registry.example.com/app:1.2.3", "cyclonedx", "my-sbom-bucket", "out/clickbom.json", "sboms.trivy_app_1_2_3"},
		},
		{
			name: "merge names the filters and the merged table",
			cfg: with(sensitiveConfig("github"), func(c *config.Config) {
				c.Merge, c.Include, c.Exclude = true, "*-prod.json", "old.json"
			}),
			want: []string{"merge", "include *-prod.json, exclude old.json", "cyclonedx", "my-sbom-bucket", "out/clickbom.json", "sboms.out_clickbom_merged"},
		},
		{
			name: "merge without filters has no target",
			cfg:  with(sensitiveConfig("github"), func(c *config.Config) { c.Merge = true }),
			want: []string{"merge", "", "cyclonedx", "my-sbom-bucket", "out/clickbom.json", "sboms.out_clickbom_merged"},
		},
		{
			name: "no clickhouse leaves the field empty",
			cfg:  with(sensitiveConfig("github"), func(c *config.Config) { c.ClickHouseURL = "" }),
			want: []string{"github", "ClickHouse/ClickBOM", "cyclonedx", "my-sbom-bucket", "out/clickbom.json", ""},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := buildSummary(tc.cfg)
			got := []string{s.Source, s.Target, s.Format, s.Bucket, s.Key, s.ClickHouse}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("buildSummary() = %q\nwant            %q", got, tc.want)
			}
			for _, v := range got {
				if strings.Contains(v, "SECRET") {
					t.Errorf("summary leaks a sensitive value: %q", v)
				}
			}
		})
	}
}

// isolateSensitiveEnv blanks every sensitive variable so tests do not depend
// on the ambient environment (CI sets CLICKHOUSE_PASSWORD, GITHUB_TOKEN, ...).
func isolateSensitiveEnv(t *testing.T) {
	t.Helper()
	for _, name := range config.SensitiveEnvVars() {
		t.Setenv(name, "")
	}
}

// captureLogs redirects the package logger for the duration of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// swapNotifierFactory makes every notifier main builds post to srv and records
// the webhook each one was asked for.
func swapNotifierFactory(t *testing.T, srv *httptest.Server) *[]string {
	t.Helper()
	var webhooks []string
	prev := newSlackNotifier
	newSlackNotifier = func(webhook string) *notify.SlackNotifier {
		webhooks = append(webhooks, webhook)
		return notify.NewSlackNotifier(srv.URL + "/services/T/B/X")
	}
	t.Cleanup(func() { newSlackNotifier = prev })
	return &webhooks
}

func toSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, v := range values {
		set[v] = true
	}
	return set
}

func TestSecretsForRedaction(t *testing.T) {
	isolateSensitiveEnv(t)

	t.Run("mend adds table-name spellings and start-up secrets", func(t *testing.T) {
		got := secretsForRedaction(sensitiveConfig("mend"), []string{"SECRET_startup_aws_key"})
		set := toSet(got)
		for _, want := range []string{
			"SECRET_github_token", "SECRET-project-uuid", "SECRET_ch_password", "https://SECRET-ch.example.com:8443",
			"https://hooks.slack.com/services/SECRET/SECRET/SECRET", "SECRET-uuid-a", "SECRET-uuid-b",
			"SECRET_startup_aws_key",
			// the ClickHouse table and the table-name form of every identifier
			"mend_secret_project_uuid",
			"secret_org_uuid", "secret_project_uuid", "secret_product_uuid", "secret_org_scope_uuid",
			"secret_uuid_a", "secret_uuid_b", "secret_wiz_report",
			"SECRETprojectuuid", "SECRETuuida",
		} {
			if !set[want] {
				t.Errorf("redaction list is missing %q", want)
			}
		}
		for _, v := range got {
			if v == "" || strings.TrimSpace(v) != v {
				t.Errorf("redaction list contains an empty or untrimmed value %q", v)
			}
		}
		for _, public := range []string{"my-sbom-bucket", "out/clickbom.json", "ClickHouse/ClickBOM", "sboms", "clickbom", "cyclonedx"} {
			if set[public] {
				t.Errorf("redaction list wrongly contains non-sensitive value %q", public)
			}
		}
	})
	t.Run("wiz adds its table name", func(t *testing.T) {
		set := toSet(secretsForRedaction(sensitiveConfig("wiz"), nil))
		if !set["wiz_secret_wiz_report"] || !set["secret_wiz_report"] || !set["SECRETwizreport"] {
			t.Errorf("wiz table-name spellings missing from %v", set)
		}
	})
	t.Run("github does not redact its public table name", func(t *testing.T) {
		set := toSet(secretsForRedaction(sensitiveConfig("github"), nil))
		if set["clickhouse_clickbom"] || set["secret_project_uuid"] {
			t.Error("github runs must not add table-name spellings")
		}
	})
	t.Run("merge does not redact the merged table name", func(t *testing.T) {
		cfg := with(sensitiveConfig("mend"), func(c *config.Config) { c.Merge = true })
		if set := toSet(secretsForRedaction(cfg, nil)); set["out_clickbom_merged"] {
			t.Error("merged table name is public and must not be redacted")
		}
	})
	t.Run("minimal config yields no empty values", func(t *testing.T) {
		cfg := &config.Config{SBOMSource: "github", S3Bucket: "b", Repository: "o/r"}
		if got := secretsForRedaction(cfg, nil); len(got) != 0 {
			t.Errorf("with nothing sensitive configured, secretsForRedaction() = %q, want none", got)
		}
	})
}

func TestConfigFailureEvent(t *testing.T) {
	isolateSensitiveEnv(t)
	t.Setenv("GITHUB_REPOSITORY", "org/repo")
	t.Setenv("GITHUB_RUN_ID", "5")
	t.Setenv("CLICKHOUSE_URL", "http://SECRET-host:8123")
	cause := errors.New("configuration error: invalid clickhouse URL format: http://SECRET-host:8123")

	ev := configFailureEvent(cause, 3*time.Second)
	if ev.Err != cause || ev.Duration != 3*time.Second {
		t.Errorf("event = %+v", ev)
	}
	if ev.Run.Repository != "org/repo" || ev.Run.RunID != "5" {
		t.Errorf("run context not read from env: %+v", ev.Run)
	}
	if ev.Summary != (notify.Summary{}) {
		t.Errorf("config failures must not carry an unvalidated summary: %+v", ev.Summary)
	}
	if !reflect.DeepEqual(ev.Redact, []string{"http://SECRET-host:8123"}) {
		t.Errorf("redaction list = %q, want exactly the raw CLICKHOUSE_URL", ev.Redact)
	}
}

func TestNotifyConfigFailure_WithoutValidWebhookIsNoop(t *testing.T) {
	isolateSensitiveEnv(t)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	webhooks := swapNotifierFactory(t, srv)
	logs := captureLogs(t)

	for _, value := range []string{"", "https://evil.example/services/x", "https://hooks.slack.com/triggers/x", "not a url"} {
		t.Setenv("SLACK_WEBHOOK_URL", value)
		notifyConfigFailure(context.Background(), errors.New("boom"), time.Second)
	}
	if len(*webhooks) != 0 || calls != 0 || logs.Len() != 0 {
		t.Errorf("expected no notifier, no request and no log; got webhooks=%q calls=%d logs=%q", *webhooks, calls, logs.String())
	}
}

func TestNotifyConfigFailure_PostsRedactedFailure(t *testing.T) {
	isolateSensitiveEnv(t)
	t.Setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X")
	t.Setenv("CLICKHOUSE_URL", "http://SECRET-host:8123")
	t.Setenv("MEND_PROJECT_UUIDS", "SECRET-uuid-a, SECRET-uuid-b")
	t.Setenv("GITHUB_REPOSITORY", "org/repo")
	t.Setenv("GITHUB_RUN_ID", "5")
	t.Setenv("GITHUB_RUN_ATTEMPT", "1")

	var posted string
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		posted = string(body)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	webhooks := swapNotifierFactory(t, srv)
	logs := captureLogs(t)

	cause := errors.New("configuration error: sanitization failed: invalid UUID format for MEND_PROJECT_UUIDS: SECRET-uuid-b (after http://SECRET-host:8123)")
	notifyConfigFailure(context.Background(), cause, time.Second)

	if calls != 1 || !reflect.DeepEqual(*webhooks, []string{"https://hooks.slack.com/services/T/B/X"}) {
		t.Fatalf("calls = %d, webhooks = %q; want one notifier for the validated webhook and one request", calls, *webhooks)
	}
	if !strings.Contains(posted, "ClickBOM failed") || !strings.Contains(posted, "org/repo/actions/runs/5") {
		t.Errorf("payload lacks the failure header or run link: %s", posted)
	}
	for _, leaked := range []string{"SECRET-host", "SECRET-uuid-b", "8123"} {
		if strings.Contains(posted, leaked) {
			t.Errorf("payload leaks %q: %s", leaked, posted)
		}
	}
	for _, field := range []string{"*Source*", "*Output*", "*ClickHouse*"} {
		if strings.Contains(posted, field) {
			t.Errorf("config failures must not carry a summary field %s: %s", field, posted)
		}
	}
	if strings.Contains(logs.String(), "SECRET") || strings.Contains(logs.String(), "notification failed") {
		t.Errorf("unexpected log output: %s", logs.String())
	}
}

func TestNotifyOutcome_NilNotifierIsNoop(t *testing.T) {
	logs := captureLogs(t)
	notifyOutcome(context.Background(), nil, notify.Event{})
	if logs.Len() != 0 {
		t.Errorf("nil notifier must not log anything, got %q", logs.String())
	}
}

func TestNotifyOutcome_LogsDeliveryFailureAndReturns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid_payload"))
	}))
	defer srv.Close()
	logs := captureLogs(t)

	notifyOutcome(context.Background(), notify.NewSlackNotifier(srv.URL+"/services/T/B/X"), notify.Event{})

	if !strings.Contains(logs.String(), "[WARNING]") || !strings.Contains(logs.String(), "Slack notification failed") || !strings.Contains(logs.String(), "invalid_payload") {
		t.Errorf("delivery failure must be logged as a warning with Slack's token: %s", logs.String())
	}
	if strings.Contains(logs.String(), "/services/T/B/X") {
		t.Errorf("log leaks the webhook URL: %s", logs.String())
	}
}

func TestNotifyOutcome_AbandonsHangingDelivery(t *testing.T) {
	prev := notificationTimeout
	notificationTimeout = 50 * time.Millisecond
	t.Cleanup(func() { notificationTimeout = prev })

	// The handler parks every request until the test releases it, so the
	// only way notifyOutcome can return promptly is the deadline.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-release
	}))
	defer srv.Close()
	defer close(release) // runs before srv.Close, letting parked handlers finish
	logs := captureLogs(t)

	start := time.Now()
	notifyOutcome(context.Background(), notify.NewSlackNotifier(srv.URL+"/services/T/B/X"), notify.Event{})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("notifyOutcome took %s; the deadline must abandon a hanging delivery", elapsed)
	}
	if !strings.Contains(logs.String(), "Slack notification failed") {
		t.Errorf("abandoned delivery must be logged: %s", logs.String())
	}
}

// panicErr is an error whose message cannot be rendered; it stands in for any
// unexpected failure inside the notifier.
type panicErr struct{}

func (panicErr) Error() string { panic("boom SECRET_from_panic") }

func TestNotifyOutcome_RecoversFromPanic(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	logs := captureLogs(t)

	notifyOutcome(context.Background(), notify.NewSlackNotifier(srv.URL+"/services/T/B/X"), notify.Event{Err: panicErr{}})

	if calls != 0 {
		t.Errorf("a panicking payload must not be posted, got %d requests", calls)
	}
	if !strings.Contains(logs.String(), "Slack notification failed: internal error") {
		t.Errorf("recovered panic must be logged as a warning: %s", logs.String())
	}
	if strings.Contains(logs.String(), "SECRET_from_panic") {
		t.Errorf("the panic value must not be logged: %s", logs.String())
	}
}
