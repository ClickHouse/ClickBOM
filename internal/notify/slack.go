// Package notify posts a summary of a ClickBOM run to an external channel.
// Only Slack incoming webhooks are supported.
//
// Everything in this package is best effort: a notification failure is logged
// by the caller and never changes the outcome of the run. The webhook URL is a
// credential, so no code path here may log it or embed it in an error.
//
// Layering rule: values read from the environment reach the HTTP request only
// through an Event that cmd/clickbom builds. RunContextFromEnv lives here for
// convenience, but nothing on the path into post() may call it or os.Getenv:
// gosec's taint analysis (G704, run by golangci-lint in CI) flags an
// env-tainted request URL or body reaching http.Client.Do within one package.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ClickHouse/ClickBOM/pkg/logger"
)

const (
	slackMaxAttempts   = 3
	slackRetryDelay    = 2 * time.Second
	slackMaxRetryAfter = 30 * time.Second
	slackTimeout       = 15 * time.Second

	// Slack limits: 10 fields of 2000 characters per section and 3000
	// characters of section text. Escaping can grow a rune to five characters
	// ("&amp;"), so the rune caps below stay well inside those limits.
	slackMaxFields     = 10
	fieldMaxRunes      = 300
	labelMaxRunes      = 100
	slackMaxErrorRunes = 500

	// minSecretRunes: shorter values are not redacted. Replacing a one- or
	// two-character "secret" everywhere turns the text to mush and gives the
	// value away through the pattern of the replacements.
	minSecretRunes = 4

	colorSuccess = "#2eb886"
	colorFailure = "#a30200"

	blockSection = "section"
	blockContext = "context"
	textMrkdwn   = "mrkdwn"

	defaultServerURL = "https://github.com"
)

// RunContext is the non-secret GitHub Actions metadata about the workflow run,
// job and step that invoked ClickBOM. Every value comes from the default
// environment variables the runner injects into container actions, except
// JobCheckRunID, which action.yml passes in from the job-check-run-id input.
type RunContext struct {
	ServerURL        string
	Repository       string // owner/repo of the workflow, not of the SBOM
	Workflow         string
	Job              string // the job's key in the workflow file (GITHUB_JOB), not its name
	Step             string // the step id (GITHUB_ACTION); generated when the step has no id
	ActionRepository string // ClickHouse/ClickBOM
	ActionRef        string // the ref the consumer pinned, e.g. v2.0.0
	RunID            string
	RunNumber        string
	RunAttempt       string
	JobCheckRunID    string // job.check_run_id; empty on servers that do not provide it
	EventName        string
	RefName          string
	HeadRef          string // source branch of a pull request; RefName is "<n>/merge" there
	SHA              string
	Actor            string
	TriggeringActor  string // who re-ran the workflow, when that differs from Actor
	RunnerOS         string
}

// RunContextFromEnv reads the GitHub Actions default environment variables.
// Missing variables leave the field empty and are simply omitted from the
// message.
func RunContextFromEnv() RunContext {
	return RunContext{
		ServerURL:        serverURL(os.Getenv("GITHUB_SERVER_URL")),
		Repository:       os.Getenv("GITHUB_REPOSITORY"),
		Workflow:         os.Getenv("GITHUB_WORKFLOW"),
		Job:              os.Getenv("GITHUB_JOB"),
		Step:             os.Getenv("GITHUB_ACTION"),
		ActionRepository: os.Getenv("GITHUB_ACTION_REPOSITORY"),
		ActionRef:        os.Getenv("GITHUB_ACTION_REF"),
		RunID:            os.Getenv("GITHUB_RUN_ID"),
		RunNumber:        os.Getenv("GITHUB_RUN_NUMBER"),
		RunAttempt:       os.Getenv("GITHUB_RUN_ATTEMPT"),
		JobCheckRunID:    os.Getenv("CLICKBOM_JOB_CHECK_RUN_ID"),
		EventName:        os.Getenv("GITHUB_EVENT_NAME"),
		RefName:          os.Getenv("GITHUB_REF_NAME"),
		HeadRef:          os.Getenv("GITHUB_HEAD_REF"),
		SHA:              os.Getenv("GITHUB_SHA"),
		Actor:            os.Getenv("GITHUB_ACTOR"),
		TriggeringActor:  os.Getenv("GITHUB_TRIGGERING_ACTOR"),
		RunnerOS:         os.Getenv("RUNNER_OS"),
	}
}

// serverURL accepts an http(s) origin (GITHUB_SERVER_URL never carries a
// path, credentials, query or fragment) and falls back to github.com
// otherwise, so the value can be spliced into a Slack link (`<url|label>`
// breaks on `|` and `>`).
func serverURL(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "|<>") {
		return defaultServerURL
	}
	return u.Scheme + "://" + u.Host
}

// runURLRepository restricts the repository slug to characters that are safe
// inside a Slack link.
var runURLRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// runBase is "{server}/{repo}/actions/runs/{id}", or "" when the environment
// does not describe a run.
func (rc RunContext) runBase() string {
	if !runURLRepository.MatchString(rc.Repository) || !isDigits(rc.RunID) {
		return ""
	}
	return fmt.Sprintf("%s/%s/actions/runs/%s", rc.ServerURL, rc.Repository, rc.RunID)
}

// RunURL links the workflow run, pointing at the specific attempt when the
// run was re-run.
func (rc RunContext) RunURL() string {
	base := rc.runBase()
	if base == "" {
		return ""
	}
	if n, err := strconv.Atoi(rc.RunAttempt); err == nil && n > 1 {
		base += fmt.Sprintf("/attempts/%d", n)
	}
	return base
}

// JobURL links the job itself, which is what distinguishes matrix legs that
// share a job key. Each attempt's job has its own check run id, so no attempt
// segment is added. Returns "" when the id is unknown.
func (rc RunContext) JobURL() string {
	base := rc.runBase()
	if base == "" || !isDigits(rc.JobCheckRunID) {
		return ""
	}
	return base + "/job/" + rc.JobCheckRunID
}

// Link is the most specific link available: the job, else the run.
func (rc RunContext) Link() string {
	if u := rc.JobURL(); u != "" {
		return u
	}
	return rc.RunURL()
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Summary is the non-secret description of what ClickBOM was asked to do.
// The caller builds it from the configuration; nothing in it may derive from
// an input the README marks Sensitive.
type Summary struct {
	Source     string // github, mend, wiz, trivy, or merge
	Target     string // what was processed: owner/repo, an image, "project scope", merge filters
	Format     string // cyclonedx or spdxjson
	Bucket     string
	Key        string
	ClickHouse string // "db.table", or "db" when the table name would be sensitive; "" when disabled
}

// Event is one finished run.
type Event struct {
	Run      RunContext
	Summary  Summary
	Err      error // nil on success
	Duration time.Duration
	// Redact lists secret values that must never appear in the posted error
	// text; see redact for the variants that are matched.
	Redact []string
}

// SlackNotifier posts Events to a Slack incoming webhook.
type SlackNotifier struct {
	webhookURL  string
	client      *http.Client
	maxAttempts int
	retryDelay  time.Duration
	sleep       func(context.Context, time.Duration) error
	now         func() time.Time
}

// NewSlackNotifier returns a notifier for webhookURL, or nil when the URL is
// empty. A nil *SlackNotifier is safe to use: Notify is a no-op.
func NewSlackNotifier(webhookURL string) *SlackNotifier {
	if webhookURL == "" {
		return nil
	}
	return &SlackNotifier{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: slackTimeout,
			// Never follow a redirect: the webhook path is the credential and
			// Go would re-send it (as URL and Referer) to wherever the
			// response points. A 3xx surfaces as a permanent failure instead.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		maxAttempts: slackMaxAttempts,
		retryDelay:  slackRetryDelay,
		sleep:       sleepContext,
		now:         time.Now,
	}
}

// Notify posts ev. Transient failures (network errors, 429, 5xx) are retried
// with a growing delay, honouring Retry-After up to a cap; any other status,
// including redirects, is permanent. The returned error never contains the
// webhook URL.
func (n *SlackNotifier) Notify(ctx context.Context, ev Event) error {
	if n == nil {
		return nil
	}
	body, err := json.Marshal(buildPayload(ev))
	if err != nil {
		return fmt.Errorf("encode Slack payload: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= n.maxAttempts; attempt++ {
		retryAfter, retryable, err := n.post(ctx, body)
		if err == nil {
			logger.Success("Slack notification sent")
			return nil
		}
		lastErr = err
		if !retryable || attempt == n.maxAttempts {
			break
		}
		delay := n.retryDelay * time.Duration(attempt)
		if retryAfter > delay {
			delay = retryAfter
		}
		if delay > slackMaxRetryAfter {
			delay = slackMaxRetryAfter
		}
		logger.Warning("Slack notification attempt %d/%d failed: %v (retrying in %s)", attempt, n.maxAttempts, err, delay)
		if err := n.sleep(ctx, delay); err != nil {
			return err
		}
	}
	return lastErr
}

// post performs one webhook call. It reports whether a failure is worth
// retrying and any Retry-After the server asked for.
func (n *SlackNotifier) post(ctx context.Context, body []byte) (retryAfter time.Duration, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		return 0, false, fmt.Errorf("build Slack request: %w", stripURL(err))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return 0, true, fmt.Errorf("post to Slack: %w", stripURL(err))
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			logger.Warning("Failed to close Slack response body: %v", cerr)
		}
	}()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	reason := responseToken(respBody)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return 0, false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return parseRetryAfter(resp.Header.Get("Retry-After"), n.now()), true,
			fmt.Errorf("slack webhook returned status %d%s", resp.StatusCode, reason)
	default:
		return 0, false, fmt.Errorf("slack webhook returned status %d%s", resp.StatusCode, reason)
	}
}

// slackTokenRE matches Slack's short error bodies ("ok", "invalid_payload",
// "no_service", "channel_not_found", ...).
var slackTokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// responseToken quotes a Slack error token and withholds anything else: an
// intermediary's error page may echo the request path, which is the secret.
func responseToken(body []byte) string {
	s := strings.TrimSpace(string(body))
	switch {
	case s == "":
		return ""
	case slackTokenRE.MatchString(s):
		return ": " + s
	default:
		return " (response body withheld)"
	}
}

// parseRetryAfter understands both forms of Retry-After: delay-seconds and an
// HTTP-date. Anything else means "no hint".
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// stripURL unwraps *url.Error so the webhook URL it quotes never reaches logs
// or error output. Same purpose as stripURL in internal/sbom/github.go, which
// protects pre-signed download URLs.
func stripURL(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}

// sleepContext is a context-aware time.Sleep (also in internal/sbom/github.go).
func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Slack message model. The header lives in top-level blocks so `text` is only
// the notification fallback; the details sit in a colour-coded attachment.
// The link is mrkdwn rather than a Block Kit button because a `url` button
// still sends an interaction payload that a webhook-only app cannot answer.
type payload struct {
	Text        string       `json:"text"`
	Blocks      []block      `json:"blocks"`
	Attachments []attachment `json:"attachments,omitempty"`
	UnfurlLinks bool         `json:"unfurl_links"`
	UnfurlMedia bool         `json:"unfurl_media"`
}

type attachment struct {
	Color  string  `json:"color"`
	Blocks []block `json:"blocks"`
}

type block struct {
	Type     string `json:"type"`
	Text     *text  `json:"text,omitempty"`
	Fields   []text `json:"fields,omitempty"`
	Elements []text `json:"elements,omitempty"`
}

type text struct {
	Type string `json:"type"`
	Text string `json:"text"`
	// Verbatim stops Slack from auto-linking URLs and parsing mentions in the
	// text; set on the error block, whose content is not ours.
	Verbatim bool `json:"verbatim,omitempty"`
}

func mrkdwn(s string) *text { return &text{Type: textMrkdwn, Text: s} }

// buildPayload renders ev as a Slack message. Every value that came from the
// environment, the configuration or an error is escaped so it cannot inject
// mrkdwn links, mentions or formatting.
func buildPayload(ev Event) payload {
	status, emoji, color := "succeeded", ":white_check_mark:", colorSuccess
	if ev.Err != nil {
		status, emoji, color = "failed", ":x:", colorFailure
	}

	label := runLabel(ev.Run)
	header := fmt.Sprintf("%s *ClickBOM %s*", emoji, status)
	fallback := "ClickBOM " + status
	if label != "" {
		fallback += ": " + label
		if link := ev.Run.Link(); link != "" {
			header += fmt.Sprintf(" in <%s|%s>", link, slackEscape(label))
		} else {
			header += " in " + slackEscape(label)
		}
	}

	var fields []text
	fields = appendField(fields, "Workflow", ev.Run.Workflow)
	fields = appendField(fields, "Job", ev.Run.Job)
	fields = appendField(fields, "Step", ev.Run.Step)
	fields = appendField(fields, "Trigger", trigger(ev.Run))
	fields = appendField(fields, "Source", joinNonEmpty(" · ", ev.Summary.Source, ev.Summary.Target))
	fields = appendField(fields, "Output", output(ev.Summary))
	fields = appendField(fields, "ClickHouse", ev.Summary.ClickHouse)
	if ev.Duration > 0 {
		fields = appendField(fields, "Duration", ev.Duration.Round(time.Second).String())
	}

	var details []block
	if len(fields) > 0 {
		details = append(details, block{Type: blockSection, Fields: fields})
	}
	if ev.Err != nil {
		details = append(details, block{Type: blockSection, Text: &text{
			Type:     textMrkdwn,
			Text:     "```" + slackEscape(errorText(ev.Err, ev.Redact)) + "```",
			Verbatim: true,
		}})
	}
	if footer := footer(ev.Run); footer != "" {
		details = append(details, block{Type: blockContext, Elements: []text{{Type: textMrkdwn, Text: slackEscape(footer)}}})
	}

	p := payload{
		Text:   slackEscape(fallback),
		Blocks: []block{{Type: blockSection, Text: mrkdwn(header)}},
	}
	if len(details) > 0 {
		p.Attachments = []attachment{{Color: color, Blocks: details}}
	}
	return p
}

// appendField adds a "*Name*\nvalue" field, skipping empty values, capping the
// value length and honouring Slack's limit of ten fields per section.
func appendField(fields []text, name, value string) []text {
	value = strings.TrimSpace(value)
	if value == "" || len(fields) >= slackMaxFields {
		return fields
	}
	return append(fields, text{Type: textMrkdwn, Text: "*" + name + "*\n" + slackEscape(truncateRunes(value, fieldMaxRunes))})
}

// runLabel is "owner/repo · workflow #12 (attempt 2)" with missing parts left
// out. Repository and workflow names are capped so the header (which also
// carries the link) stays inside Slack's 3000-character section limit.
func runLabel(rc RunContext) string {
	label := joinNonEmpty(" · ", truncateRunes(rc.Repository, labelMaxRunes), truncateRunes(rc.Workflow, labelMaxRunes))
	if rc.RunNumber != "" {
		label = joinNonEmpty(" ", label, "#"+rc.RunNumber)
	}
	if n, err := strconv.Atoi(rc.RunAttempt); err == nil && n > 1 {
		label = joinNonEmpty(" ", label, fmt.Sprintf("(attempt %d)", n))
	}
	return label
}

// trigger is "push on main @ abc1234 by octocat" with missing parts left out.
// Pull requests show their source branch rather than "<n>/merge", and a re-run
// names the person who re-ran it.
func trigger(rc RunContext) string {
	parts := []string{rc.EventName}
	ref := rc.RefName
	if rc.HeadRef != "" {
		ref = rc.HeadRef
	}
	if ref != "" {
		parts = append(parts, "on "+ref)
	}
	if rc.SHA != "" {
		parts = append(parts, "@ "+shortSHA(rc.SHA))
	}
	actor := rc.Actor
	if n, err := strconv.Atoi(rc.RunAttempt); err == nil && n > 1 && rc.TriggeringActor != "" {
		actor = rc.TriggeringActor
	}
	if actor != "" {
		parts = append(parts, "by "+actor)
	}
	return joinNonEmpty(" ", parts...)
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func output(s Summary) string {
	if s.Bucket == "" {
		return ""
	}
	out := "s3://" + s.Bucket
	if s.Key != "" {
		out += "/" + s.Key
	}
	if s.Format != "" {
		out += " (" + s.Format + ")"
	}
	return out
}

// footer names the ClickBOM release that ran and the runner OS. Both are
// absent for local (`uses: ./`) and docker:// references, in which case the
// footer is omitted rather than rendered as "@".
func footer(rc RunContext) string {
	var parts []string
	if rc.ActionRepository != "" {
		action := rc.ActionRepository
		if rc.ActionRef != "" {
			action += "@" + rc.ActionRef
		}
		parts = append(parts, action)
	}
	if rc.RunnerOS != "" {
		parts = append(parts, rc.RunnerOS)
	}
	return joinNonEmpty(" · ", parts...)
}

func joinNonEmpty(sep string, parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, sep)
}

var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// slackEscape applies the three escapes Slack requires in mrkdwn text. The
// replacer handles all three in one pass, so "&" is never double-escaped.
func slackEscape(s string) string { return slackEscaper.Replace(s) }

// errorText prepares an error for the fenced failure block: the first line
// only (tool output dumps follow the first newline), scrubbed and redacted,
// capped, and with code fences neutralised so it cannot close the block.
func errorText(err error, secrets []string) string {
	msg := err.Error()
	if i := strings.IndexAny(msg, "\r\n"); i >= 0 {
		msg = msg[:i]
	}
	msg = truncateRunes(redact(msg, secrets), slackMaxErrorRunes)
	for strings.Contains(msg, "```") {
		msg = strings.ReplaceAll(msg, "```", "'''")
	}
	if strings.TrimSpace(msg) == "" {
		return "(no details)"
	}
	return msg
}

var (
	urlRE = regexp.MustCompile(`https?://[^\s"'<>` + "`" + `]+`)
	// authHeaderRE matches "Bearer <token>" and "Basic <base64>" as echoed request
	// headers; looksLikeCredential keeps prose such as "basic validation" intact.
	authHeaderRE = regexp.MustCompile(`(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/=-]+)`)
	// ipPortRE matches the socket addresses in *net.OpError text ("dial tcp
	// 3.226.14.9:8443", "[2600::1]:8443", "[fe80::1%en0]:8443"): the resolved
	// address of a host that may itself be sensitive, which no configured value
	// can match.
	ipPortRE      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b|\[[0-9a-fA-F:.]+(?:%(?:25)?[A-Za-z0-9_.-]+)?\]:\d{1,5}`)
	awsKeyIDRE    = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	githubTokenRE = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`)
	kvSecretRE    = regexp.MustCompile(`(?i)\b(X-Amz-Signature|X-Amz-Credential|X-Amz-Security-Token|signature|sig|token|access_token|password)=[^\s&"'<>]+`)
)

// scrub removes credential shapes that no configuration value can predict:
// the userinfo and query string of every URL (pre-signed download URLs carry
// their signature there), bearer and basic auth headers, socket addresses,
// AWS access key ids, GitHub tokens and signature-like key=value pairs.
func scrub(s string) string {
	s = urlRE.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "***"
		}
		return u.Scheme + "://" + u.Host + u.EscapedPath()
	})
	s = scrubAuthHeaders(s)
	s = ipPortRE.ReplaceAllLiteralString(s, "***")
	s = awsKeyIDRE.ReplaceAllLiteralString(s, "***")
	s = githubTokenRE.ReplaceAllLiteralString(s, "***")
	return kvSecretRE.ReplaceAllString(s, "$1=***")
}

// scrubAuthHeaders blanks the token of an echoed Authorization header while
// leaving ordinary prose ("basic validation", "bearer token") untouched.
func scrubAuthHeaders(s string) string {
	return authHeaderRE.ReplaceAllStringFunc(s, func(m string) string {
		parts := authHeaderRE.FindStringSubmatch(m)
		if len(parts) != 3 || !looksLikeCredential(parts[2]) {
			return m
		}
		return strings.ToUpper(parts[1][:1]) + strings.ToLower(parts[1][1:]) + " ***"
	})
}

// looksLikeCredential tells a token from an English word: tokens are long or
// carry digits, punctuation or a capital letter after the first character.
func looksLikeCredential(tok string) bool {
	if len(tok) >= 20 {
		return true
	}
	for i, r := range tok {
		switch {
		case r >= '0' && r <= '9', strings.ContainsRune("._~+/=-", r):
			return true
		case r >= 'A' && r <= 'Z' && i > 0:
			return true
		}
	}
	return false
}

// redact scrubs s and then replaces every secret with "***". Longer needles
// are applied first so a secret that contains another one is removed whole;
// matching ignores ASCII case because hosts and hex identifiers may be
// re-cased by the libraries that formatted the error.
func redact(s string, secrets []string) string {
	s = scrub(s)
	needles := expandSecrets(secrets)
	sort.Slice(needles, func(i, j int) bool { return len(needles[i]) > len(needles[j]) })
	for _, needle := range needles {
		s = replaceFold(s, needle, "***")
	}
	return s
}

// replaceFold replaces every occurrence of needle in s with repl, ignoring
// ASCII case. It works on bytes instead of compiling a regexp per needle: a
// needle holding invalid UTF-8 (a binary secret) must never panic, and the
// regexp panic message would have quoted the secret.
func replaceFold(s, needle, repl string) string {
	if needle == "" || len(needle) > len(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if hasPrefixFold(s[i:], needle) {
			b.WriteString(repl)
			i += len(needle)
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// hasPrefixFold reports whether s starts with prefix, ignoring ASCII case.
func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		a, c := s[i], prefix[i]
		if 'A' <= a && a <= 'Z' {
			a += 'a' - 'A'
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if a != c {
			return false
		}
	}
	return true
}

// expandSecrets adds, for each secret, its trailing-slash-trimmed form, its
// query- and path-escaped forms and, when it parses as a URL, its host with
// and without port. Empty and very short values are dropped so nothing
// matches everywhere.
func expandSecrets(secrets []string) []string {
	seen := make(map[string]bool)
	var out []string
	keep := func(v string) {
		v = strings.TrimSpace(v)
		if utf8.RuneCountInString(v) < minSecretRunes || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		keep(secret)
		keep(strings.TrimRight(secret, "/"))
		keep(url.QueryEscape(secret))
		keep(url.PathEscape(secret))
		if u, err := url.Parse(secret); err == nil && u.Scheme != "" && u.Host != "" {
			keep(u.Host)
			keep(u.Hostname())
		}
	}
	return out
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	return string(runes[:n]) + "…"
}
