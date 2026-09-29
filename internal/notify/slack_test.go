package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sampleRun() RunContext {
	return RunContext{
		ServerURL:        "https://github.com",
		Repository:       "ClickHouse/sbom",
		Workflow:         "Weekly SBOMs",
		Job:              "github-prod",
		Step:             "__ClickHouse_ClickBOM",
		ActionRepository: "ClickHouse/ClickBOM",
		ActionRef:        "v2.0.0",
		RunID:            "123456789",
		RunNumber:        "42",
		RunAttempt:       "1",
		JobCheckRunID:    "987654321",
		EventName:        "schedule",
		RefName:          "main",
		SHA:              "0123456789abcdef0123456789abcdef01234567",
		Actor:            "octocat",
		RunnerOS:         "Linux",
	}
}

func sampleSummary() Summary {
	return Summary{
		Source:     "github",
		Target:     "ClickHouse/ClickBOM",
		Format:     "cyclonedx",
		Bucket:     "my-sbom-bucket",
		Key:        "clickbom.json",
		ClickHouse: "default.clickhouse_clickbom",
	}
}

const webhookPath = "/services/T000/B000/SECRET"

// newTestNotifier points a notifier at srv with instant, recorded sleeps and a
// fixed clock.
func newTestNotifier(srv *httptest.Server, slept *[]time.Duration) *SlackNotifier {
	n := NewSlackNotifier(srv.URL + webhookPath)
	n.client.Transport = srv.Client().Transport
	n.sleep = func(_ context.Context, d time.Duration) error {
		*slept = append(*slept, d)
		return nil
	}
	n.now = func() time.Time { return time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC) }
	return n
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

func TestRunContextFromEnv(t *testing.T) {
	env := map[string]string{
		"GITHUB_SERVER_URL":         "https://github.example.com/",
		"GITHUB_REPOSITORY":         "org/repo",
		"GITHUB_WORKFLOW":           "CI",
		"GITHUB_JOB":                "build",
		"GITHUB_ACTION":             "clickbom",
		"GITHUB_ACTION_REPOSITORY":  "ClickHouse/ClickBOM",
		"GITHUB_ACTION_REF":         "v2.1.0",
		"GITHUB_RUN_ID":             "99",
		"GITHUB_RUN_NUMBER":         "7",
		"GITHUB_RUN_ATTEMPT":        "2",
		"CLICKBOM_JOB_CHECK_RUN_ID": "555",
		"GITHUB_EVENT_NAME":         "pull_request",
		"GITHUB_REF_NAME":           "12/merge",
		"GITHUB_HEAD_REF":           "feature/x",
		"GITHUB_SHA":                "abcdef1234567890",
		"GITHUB_ACTOR":              "octocat",
		"GITHUB_TRIGGERING_ACTOR":   "rerunner",
		"RUNNER_OS":                 "Linux",
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	got := RunContextFromEnv()
	want := RunContext{
		ServerURL: "https://github.example.com", Repository: "org/repo", Workflow: "CI", Job: "build",
		Step: "clickbom", ActionRepository: "ClickHouse/ClickBOM", ActionRef: "v2.1.0", RunID: "99",
		RunNumber: "7", RunAttempt: "2", JobCheckRunID: "555", EventName: "pull_request", RefName: "12/merge",
		HeadRef: "feature/x", SHA: "abcdef1234567890", Actor: "octocat", TriggeringActor: "rerunner", RunnerOS: "Linux",
	}
	if got != want {
		t.Errorf("RunContextFromEnv() = %+v, want %+v", got, want)
	}
}

func TestServerURL(t *testing.T) {
	tests := map[string]string{
		"":                              defaultServerURL,
		"https://github.com":            "https://github.com",
		"https://ghe.example.com/":      "https://ghe.example.com",
		" http://ghe.internal:8080 ":    "http://ghe.internal:8080",
		"not a url":                     defaultServerURL,
		"ftp://ghe.example.com":         defaultServerURL,
		"https://user@ghe.example.com":  defaultServerURL,
		"https://ghe.example.com/?q=1":  defaultServerURL,
		"https://ghe.example.com/#frag": defaultServerURL,
		"https://ghe.example.com/a|b":   defaultServerURL,
		"https://ghe.example.com/x>y":   defaultServerURL,
	}
	for in, want := range tests {
		if got := serverURL(in); got != want {
			t.Errorf("serverURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunURL(t *testing.T) {
	tests := []struct {
		name string
		rc   RunContext
		want string
	}{
		{name: "first attempt", rc: RunContext{ServerURL: "https://github.com", Repository: "o/r", RunID: "1", RunAttempt: "1"}, want: "https://github.com/o/r/actions/runs/1"},
		{name: "no attempt given", rc: RunContext{ServerURL: "https://github.com", Repository: "o/r", RunID: "1"}, want: "https://github.com/o/r/actions/runs/1"},
		{name: "re-run links the attempt", rc: RunContext{ServerURL: "https://github.com", Repository: "o/r", RunID: "1", RunAttempt: "3"}, want: "https://github.com/o/r/actions/runs/1/attempts/3"},
		{name: "enterprise server", rc: RunContext{ServerURL: "https://ghe.example.com", Repository: "o/r", RunID: "1"}, want: "https://ghe.example.com/o/r/actions/runs/1"},
		{name: "missing repository", rc: RunContext{ServerURL: "https://github.com", RunID: "1"}, want: ""},
		{name: "missing run id", rc: RunContext{ServerURL: "https://github.com", Repository: "o/r"}, want: ""},
		{name: "non-numeric run id", rc: RunContext{ServerURL: "https://github.com", Repository: "o/r", RunID: "1|evil"}, want: ""},
		{name: "repository with link-breaking chars", rc: RunContext{ServerURL: "https://github.com", Repository: "o/r|<x>", RunID: "1"}, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rc.RunURL(); got != tc.want {
				t.Errorf("RunURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestJobURLAndLink(t *testing.T) {
	rc := RunContext{ServerURL: "https://github.com", Repository: "o/r", RunID: "1", RunAttempt: "2", JobCheckRunID: "77"}
	if got := rc.JobURL(); got != "https://github.com/o/r/actions/runs/1/job/77" {
		t.Errorf("JobURL() = %q; the job link must not carry an attempt segment", got)
	}
	if got := rc.Link(); got != rc.JobURL() {
		t.Errorf("Link() = %q, want the job URL", got)
	}

	rc.JobCheckRunID = ""
	if got := rc.JobURL(); got != "" {
		t.Errorf("JobURL() without an id = %q, want empty", got)
	}
	if got := rc.Link(); got != "https://github.com/o/r/actions/runs/1/attempts/2" {
		t.Errorf("Link() without a job id = %q, want the run attempt URL", got)
	}

	rc.JobCheckRunID = "77|evil"
	if got := rc.JobURL(); got != "" {
		t.Errorf("JobURL() with a non-numeric id = %q, want empty", got)
	}
	if got := (RunContext{JobCheckRunID: "77"}).JobURL(); got != "" {
		t.Errorf("JobURL() without a run = %q, want empty", got)
	}
}

func TestNewSlackNotifier(t *testing.T) {
	if NewSlackNotifier("") != nil {
		t.Fatal("expected nil notifier for empty URL")
	}
	var nilNotifier *SlackNotifier
	if err := nilNotifier.Notify(context.Background(), Event{}); err != nil {
		t.Fatalf("nil notifier Notify() = %v, want nil", err)
	}
	n := NewSlackNotifier("https://hooks.slack.com/services/x")
	if n == nil || n.maxAttempts != slackMaxAttempts || n.client.Timeout != slackTimeout {
		t.Fatalf("NewSlackNotifier returned %+v", n)
	}
	if n.client.CheckRedirect == nil || n.client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Error("client must refuse to follow redirects")
	}
}

// fieldMap turns a fields section into name -> value.
func fieldMap(t *testing.T, b block) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range b.Fields {
		name, value, ok := strings.Cut(f.Text, "\n")
		if !ok {
			t.Fatalf("field %q has no name/value separator", f.Text)
		}
		out[strings.Trim(name, "*")] = value
	}
	return out
}

func TestBuildPayload_Success(t *testing.T) {
	p := buildPayload(Event{Run: sampleRun(), Summary: sampleSummary(), Duration: 83*time.Second + 400*time.Millisecond})

	if p.Text != "ClickBOM succeeded: ClickHouse/sbom · Weekly SBOMs #42" {
		t.Errorf("fallback text = %q", p.Text)
	}
	if p.UnfurlLinks || p.UnfurlMedia {
		t.Error("unfurling must be disabled")
	}
	if len(p.Blocks) != 1 || p.Blocks[0].Text == nil {
		t.Fatalf("expected one header block, got %+v", p.Blocks)
	}
	wantHeader := ":white_check_mark: *ClickBOM succeeded* in <https://github.com/ClickHouse/sbom/actions/runs/123456789/job/987654321|ClickHouse/sbom · Weekly SBOMs #42>"
	if got := p.Blocks[0].Text.Text; got != wantHeader {
		t.Errorf("header = %q\nwant     %q", got, wantHeader)
	}
	if len(p.Attachments) != 1 || p.Attachments[0].Color != colorSuccess {
		t.Fatalf("attachments = %+v", p.Attachments)
	}
	blocks := p.Attachments[0].Blocks
	if len(blocks) != 2 || blocks[0].Type != blockSection || blocks[1].Type != blockContext {
		t.Fatalf("expected [section, context] blocks, got %+v", blocks)
	}
	fields := fieldMap(t, blocks[0])
	want := map[string]string{
		"Workflow":   "Weekly SBOMs",
		"Job":        "github-prod",
		"Step":       "__ClickHouse_ClickBOM",
		"Trigger":    "schedule on main @ 0123456 by octocat",
		"Source":     "github · ClickHouse/ClickBOM",
		"Output":     "s3://my-sbom-bucket/clickbom.json (cyclonedx)",
		"ClickHouse": "default.clickhouse_clickbom",
		"Duration":   "1m23s",
	}
	for k, v := range want {
		if fields[k] != v {
			t.Errorf("field %s = %q, want %q", k, fields[k], v)
		}
	}
	if len(fields) != len(want) {
		t.Errorf("fields = %v, want exactly %d", fields, len(want))
	}
	if got := blocks[1].Elements[0].Text; got != "ClickHouse/ClickBOM@v2.0.0 · Linux" {
		t.Errorf("context = %q", got)
	}

	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"unfurl_links":false`, `"unfurl_media":false`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("JSON lacks %s: %s", want, raw)
		}
	}
	if strings.Contains(string(raw), `"verbatim"`) {
		t.Errorf("success payload must not mark text verbatim: %s", raw)
	}
}

func TestBuildPayload_FailureRedactsAndEscapes(t *testing.T) {
	run := sampleRun()
	run.RunAttempt = "2"
	run.TriggeringActor = "rerunner"
	run.RefName = "feature/<b>bold</b>&co"
	err := errors.New(`failed to upload to ClickHouse: Post "https://ch.example.com:8443/?query=INSERT+INTO+default.mend_dead_beef": dial tcp: lookup CH.EXAMPLE.COM: no such host; token=ghp_abc123 <script> <!channel>`)
	p := buildPayload(Event{
		Run:     run,
		Summary: sampleSummary(),
		Err:     err,
		Redact:  []string{"https://ch.example.com:8443/", "ghp_abc123", "mend_dead_beef", "", "   "},
	})

	if p.Attachments[0].Color != colorFailure {
		t.Errorf("color = %q, want failure colour", p.Attachments[0].Color)
	}
	header := p.Blocks[0].Text.Text
	if !strings.Contains(header, ":x: *ClickBOM failed*") ||
		!strings.Contains(header, "/actions/runs/123456789/job/987654321|ClickHouse/sbom · Weekly SBOMs #42 (attempt 2)>") {
		t.Errorf("header = %q", header)
	}

	var errBlock, fieldsBlock *block
	for i := range p.Attachments[0].Blocks {
		b := &p.Attachments[0].Blocks[i]
		switch {
		case b.Type == blockSection && b.Text != nil:
			errBlock = b
		case b.Type == blockSection && b.Fields != nil:
			fieldsBlock = b
		}
	}
	if errBlock == nil || fieldsBlock == nil {
		t.Fatalf("missing error or fields block: %+v", p.Attachments[0].Blocks)
	}
	if !errBlock.Text.Verbatim {
		t.Error("error text must be verbatim so Slack does not auto-link or parse it")
	}
	got := errBlock.Text.Text
	for _, leaked := range []string{"ch.example.com", "CH.EXAMPLE.COM", "8443", "ghp_abc123", "mend_dead_beef", "<script>", "<!channel>", "query="} {
		if strings.Contains(got, leaked) {
			t.Errorf("error text leaks %q: %s", leaked, got)
		}
	}
	if !strings.HasPrefix(got, "```") || !strings.HasSuffix(got, "```") {
		t.Errorf("error text is not fenced: %s", got)
	}
	if !strings.Contains(got, "***") || !strings.Contains(got, "&lt;script&gt;") || !strings.Contains(got, "&lt;!channel&gt;") {
		t.Errorf("error text not redacted/escaped: %s", got)
	}

	fields := fieldMap(t, *fieldsBlock)
	if want := "schedule on feature/&lt;b&gt;bold&lt;/b&gt;&amp;co @ 0123456 by rerunner"; fields["Trigger"] != want {
		t.Errorf("trigger = %q, want %q", fields["Trigger"], want)
	}
}

func TestBuildPayload_PullRequestUsesHeadRef(t *testing.T) {
	run := RunContext{EventName: "pull_request", RefName: "12/merge", HeadRef: "feature/x", Actor: "octocat", RunAttempt: "1", TriggeringActor: "someone-else"}
	if got := trigger(run); got != "pull_request on feature/x by octocat" {
		t.Errorf("trigger() = %q", got)
	}
}

func TestErrorText(t *testing.T) {
	t.Run("first line only", func(t *testing.T) {
		err := errors.New("failed to generate SBOM with Trivy: trivy failed: exit status 1\nOutput: FATAL secret-in-output\nmore")
		if got := errorText(err, nil); got != "failed to generate SBOM with Trivy: trivy failed: exit status 1" {
			t.Errorf("errorText() = %q", got)
		}
	})
	t.Run("code fences cannot close the block", func(t *testing.T) {
		got := errorText(errors.New("boom ``` <!here> ````x"), nil)
		if strings.Contains(got, "```") {
			t.Errorf("errorText() still contains a fence: %q", got)
		}
	})
	t.Run("truncated to the cap with an ellipsis", func(t *testing.T) {
		got := errorText(errors.New(strings.Repeat("é", slackMaxErrorRunes+50)), nil)
		if !strings.HasSuffix(got, "…") || len([]rune(got)) != slackMaxErrorRunes+1 {
			t.Errorf("got %d runes, suffix %q", len([]rune(got)), got[len(got)-3:])
		}
	})
	t.Run("redaction happens before truncation", func(t *testing.T) {
		secret := "SUPERSECRETVALUE0123"
		msg := strings.Repeat("a", 490) + secret + strings.Repeat("b", 200)
		got := errorText(errors.New(msg), []string{secret})
		if strings.Contains(got, secret) || strings.Contains(got, "SUPERSEC") {
			t.Errorf("secret straddling the cap leaked: %q", got[480:])
		}
		if !strings.Contains(got, "***") {
			t.Errorf("expected redaction marker in %q", got[480:])
		}
	})
	t.Run("empty error gets a placeholder", func(t *testing.T) {
		if got := errorText(errors.New("\nonly on the second line"), nil); got != "(no details)" {
			t.Errorf("errorText() = %q", got)
		}
	})
}

func TestBuildPayload_MinimalEnvironment(t *testing.T) {
	// Outside GitHub Actions nothing is known; the message must still be valid.
	p := buildPayload(Event{Summary: Summary{Source: "merge", Bucket: "b", Key: "k.json"}})
	if p.Text != "ClickBOM succeeded" {
		t.Errorf("text = %q", p.Text)
	}
	if got := p.Blocks[0].Text.Text; got != ":white_check_mark: *ClickBOM succeeded*" {
		t.Errorf("header = %q", got)
	}
	blocks := p.Attachments[0].Blocks
	if len(blocks) != 1 || len(blocks[0].Fields) != 2 {
		t.Fatalf("expected one section with Source and Output, got %+v", blocks)
	}

	// With nothing at all to say there is no attachment, and never a null blocks array.
	raw, err := json.Marshal(buildPayload(Event{}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "null") || strings.Contains(string(raw), `"attachments"`) {
		t.Errorf("empty event must not emit attachments or nulls: %s", raw)
	}
}

func TestAppendField(t *testing.T) {
	var fields []text
	fields = appendField(fields, "Empty", "   ")
	if len(fields) != 0 {
		t.Fatalf("blank value was added: %+v", fields)
	}
	fields = appendField(fields, "Name", " a & b ")
	if len(fields) != 1 || fields[0].Text != "*Name*\na &amp; b" {
		t.Fatalf("field = %+v", fields)
	}
	long := strings.Repeat("x", fieldMaxRunes+100)
	fields = appendField(fields, "Long", long)
	if got := fields[1].Text; len([]rune(got)) != len("*Long*\n")+fieldMaxRunes+1 || !strings.HasSuffix(got, "…") {
		t.Errorf("long value not capped: %d runes", len([]rune(got)))
	}
	for i := 0; i < 20; i++ {
		fields = appendField(fields, "F", "v")
	}
	if len(fields) != slackMaxFields {
		t.Errorf("got %d fields, want cap %d", len(fields), slackMaxFields)
	}
}

func TestBuildPayload_StaysWithinSlackLimits(t *testing.T) {
	long := strings.Repeat("w", 5000)
	run := sampleRun()
	run.Workflow, run.Job, run.Step, run.RefName, run.Actor = long, long, long, long, long
	s := sampleSummary()
	s.Target, s.Key, s.ClickHouse = long, long, long
	p := buildPayload(Event{Run: run, Summary: s, Err: errors.New(strings.Repeat("e&", 20000)), Duration: time.Hour})

	if len(p.Text) > 4000 {
		t.Errorf("fallback text is %d chars, want <= 4000", len(p.Text))
	}
	if len(p.Attachments) != 1 {
		t.Fatalf("want exactly one attachment, got %d", len(p.Attachments))
	}
	blocks := append([]block{}, p.Blocks...)
	blocks = append(blocks, p.Attachments[0].Blocks...)
	if len(blocks) > 50 {
		t.Errorf("%d blocks, want <= 50", len(blocks))
	}
	for _, b := range blocks {
		if b.Text != nil && len(b.Text.Text) > 3000 {
			t.Errorf("section text is %d chars, want <= 3000", len(b.Text.Text))
		}
		if len(b.Fields) > 10 {
			t.Errorf("%d fields, want <= 10", len(b.Fields))
		}
		for _, f := range b.Fields {
			if len(f.Text) > 2000 {
				t.Errorf("field text is %d chars, want <= 2000", len(f.Text))
			}
		}
		if len(b.Elements) > 10 {
			t.Errorf("%d context elements, want <= 10", len(b.Elements))
		}
	}
}

func TestRedact(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		secrets []string
		want    string
	}{
		{name: "plain value", in: "key=abc123 done", secrets: []string{"abc123"}, want: "key=*** done"},
		{name: "case-insensitive", in: "Token ABC123", secrets: []string{"abc123"}, want: "Token ***"},
		{name: "trailing slash form", in: `Post "https://ch.example.com:8443": refused`, secrets: []string{"https://ch.example.com:8443/"}, want: `Post "***": refused`},
		{name: "host of a url secret", in: "lookup ch.example.com: no such host", secrets: []string{"https://ch.example.com:8443/"}, want: "lookup ***: no such host"},
		{name: "host with port", in: "dial tcp ch.example.com:8443: refused", secrets: []string{"https://ch.example.com:8443/"}, want: "dial tcp ***: refused"},
		{name: "query-escaped form", in: "user user%40example.com rejected", secrets: []string{"user@example.com"}, want: "user *** rejected"},
		{name: "empty secrets ignored", in: "nothing here", secrets: []string{"", " "}, want: "nothing here"},
		{name: "nil secrets", in: "nothing here", secrets: nil, want: "nothing here"},
		{name: "short secrets are not substring-redacted", in: "failed to upload", secrets: []string{"e", "ail"}, want: "failed to upload"},
		{name: "longer secret wins", in: "https://x.example/abc/def", secrets: []string{"abcd", "https://x.example/abc/def"}, want: "***"},
		{name: "regex metacharacters are literal", in: "a.b*c (d)", secrets: []string{"a.b*c (d)"}, want: "***"},
		{name: "pre-signed url loses its query", in: `Get "https://blob.example.com/report.json?sig=ABC&X-Amz-Signature=DEF": 403`, want: `Get "https://blob.example.com/report.json": 403`},
		{name: "url userinfo is dropped", in: `Post "https://user:pw@ch.example.com/": refused`, want: `Post "https://ch.example.com/": refused`},
		{name: "bearer token", in: "Authorization: Bearer eyJhbGci.abc-def_123 rejected", want: "Authorization: Bearer *** rejected"},
		{name: "aws access key id", in: "key AKIAIOSFODNN7EXAMPLE used", want: "key *** used"},
		{name: "github token", in: "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 rejected", want: "token *** rejected"},
		{name: "fine-grained github token", in: "github_pat_11ABCDEFG0123456789_abcdefghijklmnop bad", want: "*** bad"},
		{name: "signature pairs", in: "signature=abc123 sig=zzz token=t0k3n", want: "signature=*** sig=*** token=***"},
		{name: "basic auth header", in: "Authorization: Basic Y2xpY2tib206U0VDUkVUcHc= rejected", want: "Authorization: Basic *** rejected"},
		{name: "socket address of a sensitive host", in: "dial tcp 3.226.14.9:8443: i/o timeout", want: "dial tcp ***: i/o timeout"},
		{name: "both ends of a reset connection", in: "read tcp 10.1.0.23:51234->3.226.14.9:8443: read: connection reset by peer", want: "read tcp ***->***: read: connection reset by peer"},
		{name: "ipv6 socket address", in: "dial tcp [2600:1f18::1]:8443: connect: connection refused", want: "dial tcp ***: connect: connection refused"},
		{name: "zoned link-local ipv6 socket address", in: "dial tcp [fe80::1%en0]:8443: connection refused", want: "dial tcp ***: connection refused"},
		{name: "percent-encoded zone in a url host", in: "dial tcp [fe80::1%25eth0]:8443: refused", want: "dial tcp ***: refused"},
		{name: "prose about basic auth is not a credential", in: "failed basic validation of SBOM; Basic authentication failed for user", want: "failed basic validation of SBOM; Basic authentication failed for user"},
		{name: "prose about bearer tokens is not a credential", in: "invalid bearer token in request; missing Bearer Token", want: "invalid bearer token in request; missing Bearer Token"},
		{name: "lower-case basic header", in: "authorization: basic dXNlcjpwYXNz", want: "authorization: Basic ***"},
		{name: "long all-letter token is still a credential", in: "Bearer abcdefghijklmnopqrstuvwxyz", want: "Bearer ***"},
		{name: "invalid utf-8 secret neither panics nor leaks", in: "boom SECRET\xff\xfeVALUE end", secrets: []string{"SECRET\xff\xfeVALUE"}, want: "boom *** end"},
		{name: "invalid utf-8 secret is still matched case-insensitively", in: "boom secret\xff\xfevalue end", secrets: []string{"SECRET\xff\xfeVALUE"}, want: "boom *** end"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := redact(tc.in, tc.secrets); got != tc.want {
				t.Errorf("redact() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSlackEscape(t *testing.T) {
	if got := slackEscape(`<https://evil|click> & "quotes" &lt;`); got != `&lt;https://evil|click&gt; &amp; "quotes" &amp;lt;` {
		t.Errorf("slackEscape() = %q", got)
	}
}

func TestNotify_PostsJSONOnce(t *testing.T) {
	var got payload
	var contentType string
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		contentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("bad JSON body: %v", err)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	var slept []time.Duration
	n := newTestNotifier(srv, &slept)
	logs := captureLogs(t)
	if err := n.Notify(context.Background(), Event{Run: sampleRun(), Summary: sampleSummary()}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if calls != 1 || len(slept) != 0 {
		t.Errorf("calls = %d, sleeps = %v; want one call and no sleeps", calls, slept)
	}
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q", contentType)
	}
	if !strings.Contains(got.Text, "ClickBOM succeeded") {
		t.Errorf("posted text = %q", got.Text)
	}
	if !strings.Contains(logs.String(), "[SUCCESS]") || !strings.Contains(logs.String(), "Slack notification sent") {
		t.Errorf("success not logged: %s", logs.String())
	}
	if strings.Contains(logs.String(), "SECRET") {
		t.Errorf("log leaks webhook URL: %s", logs.String())
	}
}

func TestNotify_RetriesServerErrorsThenSucceeds(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("rollup_error"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	var slept []time.Duration
	n := newTestNotifier(srv, &slept)
	logs := captureLogs(t)
	if err := n.Notify(context.Background(), Event{}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
	// Linear back-off: 2s then 4s.
	if len(slept) != 2 || slept[0] != 2*time.Second || slept[1] != 4*time.Second {
		t.Errorf("sleeps = %v, want [2s 4s]", slept)
	}
	if !strings.Contains(logs.String(), "status 502: rollup_error") {
		t.Errorf("Slack's error token should be logged: %s", logs.String())
	}
	if strings.Contains(logs.String(), "SECRET") {
		t.Errorf("log leaks webhook URL: %s", logs.String())
	}
}

func TestNotify_HonoursRetryAfter(t *testing.T) {
	tests := []struct {
		name   string
		header string
		status int
		want   time.Duration
	}{
		{name: "seconds", header: "7", status: http.StatusTooManyRequests, want: 7 * time.Second},
		{name: "http date", header: "Tue, 29 Sep 2026 12:00:09 GMT", status: http.StatusServiceUnavailable, want: 9 * time.Second},
		{name: "capped", header: "3600", status: http.StatusServiceUnavailable, want: slackMaxRetryAfter},
		{name: "shorter than back-off is ignored", header: "1", status: http.StatusTooManyRequests, want: 2 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				if calls == 1 {
					w.Header().Set("Retry-After", tc.header)
					w.WriteHeader(tc.status)
					return
				}
				_, _ = w.Write([]byte("ok"))
			}))
			defer srv.Close()

			var slept []time.Duration
			n := newTestNotifier(srv, &slept)
			captureLogs(t)
			if err := n.Notify(context.Background(), Event{}); err != nil {
				t.Fatalf("Notify: %v", err)
			}
			if len(slept) != 1 || slept[0] != tc.want {
				t.Errorf("sleeps = %v, want [%s]", slept, tc.want)
			}
		})
	}
}

func TestNotify_ClientErrorsArePermanent(t *testing.T) {
	tests := []struct {
		status int
		body   string
	}{
		{http.StatusBadRequest, "invalid_payload"},
		{http.StatusForbidden, "action_prohibited"},
		{http.StatusNotFound, "no_service"},
		{http.StatusGone, "channel_is_archived"},
	}
	for _, tc := range tests {
		t.Run(tc.body, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			var slept []time.Duration
			n := newTestNotifier(srv, &slept)
			logs := captureLogs(t)
			err := n.Notify(context.Background(), Event{})
			if err == nil {
				t.Fatalf("expected error for %d", tc.status)
			}
			if calls != 1 || len(slept) != 0 {
				t.Errorf("calls = %d, sleeps = %v; want a single attempt", calls, slept)
			}
			if !strings.Contains(err.Error(), "status "+strconv.Itoa(tc.status)+": "+tc.body) {
				t.Errorf("error = %q, want status and Slack token", err)
			}
			if strings.Contains(err.Error(), "SECRET") || strings.Contains(logs.String(), "SECRET") {
				t.Errorf("webhook URL leaked: err=%q logs=%s", err, logs.String())
			}
		})
	}
}
func TestNotify_DoesNotFollowRedirects(t *testing.T) {
	targetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetCalls++
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Redirect(w, r, target.URL+"/exfil", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	var slept []time.Duration
	n := newTestNotifier(srv, &slept)
	logs := captureLogs(t)
	err := n.Notify(context.Background(), Event{})
	if err == nil || !strings.Contains(err.Error(), "status 307") {
		t.Fatalf("err = %v, want a permanent status 307 failure", err)
	}
	if targetCalls != 0 {
		t.Errorf("redirect target received %d requests; the credential-bearing request must never be forwarded", targetCalls)
	}
	if calls != 1 || len(slept) != 0 {
		t.Errorf("calls = %d, sleeps = %v; a redirect must not be retried", calls, slept)
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(logs.String(), "SECRET") || strings.Contains(err.Error(), target.URL) {
		t.Errorf("leak: err=%q logs=%s", err, logs.String())
	}
}

func TestNotify_WithholdsNonTokenResponseBodies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		// An intermediary's error page that echoes the request path.
		_, _ = w.Write([]byte("<html>upstream error for " + r.URL.Path + "</html>"))
	}))
	defer srv.Close()

	var slept []time.Duration
	n := newTestNotifier(srv, &slept)
	n.maxAttempts = 2
	logs := captureLogs(t)
	err := n.Notify(context.Background(), Event{})
	if err == nil || !strings.Contains(err.Error(), "status 500 (response body withheld)") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(logs.String(), "SECRET") || strings.Contains(logs.String(), "<html>") {
		t.Errorf("response body leaked: err=%q logs=%s", err, logs.String())
	}
}

func TestNotify_GivesUpAfterMaxAttempts(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var slept []time.Duration
	n := newTestNotifier(srv, &slept)
	captureLogs(t)
	err := n.Notify(context.Background(), Event{})
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("err = %v, want status 500 error", err)
	}
	if calls != 3 || len(slept) != 2 {
		t.Errorf("calls = %d, sleeps = %d; want 3 calls and 2 sleeps", calls, len(slept))
	}
}

func TestNotify_NetworkErrorNeverQuotesURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // connection refused from here on

	var slept []time.Duration
	n := newTestNotifier(srv, &slept)
	n.maxAttempts = 2
	logs := captureLogs(t)
	err := n.Notify(context.Background(), Event{})
	if err == nil {
		t.Fatal("expected a network error")
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), srv.URL) {
		t.Errorf("error leaks webhook URL: %q", err)
	}
	if strings.Contains(logs.String(), "SECRET") || strings.Contains(logs.String(), srv.URL) {
		t.Errorf("log leaks webhook URL: %s", logs.String())
	}
	if len(slept) != 1 {
		t.Errorf("network errors should be retried once with maxAttempts=2, slept %v", slept)
	}
}

func TestNotify_StopsWhenContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	var slept []time.Duration
	n := newTestNotifier(srv, &slept)
	sleeps := 0
	n.sleep = func(ctx context.Context, _ time.Duration) error {
		sleeps++
		cancel()
		return ctx.Err()
	}
	captureLogs(t)
	err := n.Notify(ctx, Event{})
	// The sleep's own error must come back unwrapped, and there must be no
	// further attempt after it: a retry with a cancelled context would also
	// yield context.Canceled, but wrapped and after a second sleep.
	if err != context.Canceled {
		t.Errorf("err = %v, want the bare context.Canceled returned by sleep", err)
	}
	if sleeps != 1 {
		t.Errorf("sleep called %d times, want exactly once", sleeps)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	tests := map[string]time.Duration{
		"7":                             7 * time.Second,
		" 2 ":                           2 * time.Second,
		"0":                             0,
		"-1":                            0,
		"":                              0,
		"soon":                          0,
		"Tue, 29 Sep 2026 12:00:05 GMT": 5 * time.Second,
		"Tue, 29 Sep 2026 11:59:00 GMT": 0, // already in the past
	}
	for in, want := range tests {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestResponseToken(t *testing.T) {
	tests := map[string]string{
		"":                               "",
		"ok":                             ": ok",
		"invalid_payload\n":              ": invalid_payload",
		"channel-not-found":              ": channel-not-found",
		"<html>error /services/x</html>": " (response body withheld)",
		"two words":                      " (response body withheld)",
	}
	for in, want := range tests {
		if got := responseToken([]byte(in)); got != want {
			t.Errorf("responseToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSleepContext(t *testing.T) {
	if err := sleepContext(context.Background(), time.Millisecond); err != nil {
		t.Errorf("sleepContext: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled sleepContext = %v", err)
	}
}

func TestReplaceFold(t *testing.T) {
	tests := []struct{ s, needle, want string }{
		{"abcABCabc", "abc", "*********"},
		{"xAbCx", "abc", "x***x"},
		{"aaa", "aa", "***a"},
		{"short", "longer than s", "short"},
		{"anything", "", "anything"},
		{"Straße STRASSE", "straße", "*** STRASSE"}, // only ASCII letters fold
		{"bin\xff\xfe" + "bin", "BIN\xff\xfe", "***bin"},
	}
	for _, tc := range tests {
		if got := replaceFold(tc.s, tc.needle, "***"); got != tc.want {
			t.Errorf("replaceFold(%q, %q) = %q, want %q", tc.s, tc.needle, got, tc.want)
		}
	}
}
