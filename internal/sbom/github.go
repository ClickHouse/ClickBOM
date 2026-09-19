// Package sbom provides functionalities to interact with GitHub API for SBOM download.
package sbom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/ClickBOM/pkg/logger"
)

const (
	// defaultGitHubAPIBaseURL is the REST API root. Tests point baseURL at an
	// httptest server instead.
	defaultGitHubAPIBaseURL = "https://api.github.com"

	// githubAPIVersion is the REST API version the asynchronous SBOM
	// endpoints are documented under. They answer identically for older
	// versions, so this is documentation alignment rather than a requirement.
	githubAPIVersion = "2026-03-10"

	// githubSBOMMaxAttempts bounds how many times the whole
	// request -> poll -> download sequence is restarted after a transient
	// failure. Each attempt costs one call against GitHub's dependency_sbom
	// rate limit (100/hour).
	githubSBOMMaxAttempts = 3

	// githubSBOMRetryDelay is the base back-off between attempts; attempt n
	// waits n times this.
	githubSBOMRetryDelay = 30 * time.Second

	// githubSBOMMaxWait bounds how long a single report is polled. The largest
	// repository seen so far (25k packages, 52 MB of SPDX) completes in about
	// 20 s, so exceeding this means the report is stuck; the run then fails
	// instead of requesting another one.
	githubSBOMMaxWait = 10 * time.Minute

	// githubSBOMMinPollInterval and githubSBOMMaxPollInterval clamp the
	// spacing between fetch-report polls. GitHub advertises Retry-After: 1;
	// polls double from the minimum up to the maximum so a slow report is not
	// hammered.
	githubSBOMMinPollInterval = 2 * time.Second
	githubSBOMMaxPollInterval = 30 * time.Second

	// githubSBOMMaxPollErrors is how many consecutive poll failures (network
	// errors, 5xx) are tolerated before the attempt is abandoned and a fresh
	// report requested.
	githubSBOMMaxPollErrors = 5

	// githubErrorSnippetLen caps how much of an error response body is quoted
	// in error messages.
	githubErrorSnippetLen = 512

	// githubDownloadMaxRedirects bounds the https hop chain tolerated when
	// fetching the pre-signed download URL (CDN fronting); anything longer is
	// treated as a loop.
	githubDownloadMaxRedirects = 3
)

// errReportFailed marks a poll outcome that means the current report will
// never complete (GitHub dropped it or reported a generation failure). The
// poll loop stops and the caller requests a fresh report.
var errReportFailed = errors.New("SBOM report failed")

// permanentError marks a failure that retrying cannot fix: bad credentials,
// unknown repository, dependency graph disabled, poll deadline exceeded.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func permanent(err error) error { return &permanentError{err: err} }

func isPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

// GitHubClient handles interactions with the GitHub API.
type GitHubClient struct {
	token   string
	baseURL string

	// apiClient talks to the REST API and deliberately does not follow
	// redirects: fetch-report answers 302 with a pre-signed download URL, and
	// that response is handled here rather than by the transport (which would
	// otherwise decide on its own what to forward to the storage host).
	apiClient *http.Client

	// downloadClient fetches the pre-signed URL. It never carries the GitHub
	// token: the URL is authenticated by its own signature, and the storage
	// service rejects requests that also present a bearer token (HTTP 401).
	downloadClient *http.Client

	maxAttempts int
	retryDelay  time.Duration
	maxWait     time.Duration
	minPoll     time.Duration
	maxPoll     time.Duration

	// now and sleep are indirected so tests can drive the poll loop without
	// real waiting.
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// NewGitHubClient creates a new GitHubClient with the provided token. An empty
// token is allowed (public repositories); no Authorization header is sent then.
func NewGitHubClient(token string) *GitHubClient {
	return &GitHubClient{
		token:          token,
		baseURL:        defaultGitHubAPIBaseURL,
		apiClient:      newGitHubAPIClient(nil),
		downloadClient: newGitHubDownloadClient(nil),
		maxAttempts:    githubSBOMMaxAttempts,
		retryDelay:     githubSBOMRetryDelay,
		maxWait:        githubSBOMMaxWait,
		minPoll:        githubSBOMMinPollInterval,
		maxPoll:        githubSBOMMaxPollInterval,
		now:            time.Now,
		sleep:          sleepContext,
	}
}

// newGitHubAPIClient builds the non-redirecting client used for REST calls.
// transport may be nil for the default transport.
func newGitHubAPIClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		Timeout:   2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// newGitHubDownloadClient builds the client for the pre-signed download URL.
// transport may be nil for the default transport. The URL carries its own
// credentials in its query string, so redirects are followed only as a short
// https-only chain and never forward the signed URL as Referer; a hop to plain
// http is refused outright, since retrying cannot make it https.
func newGitHubDownloadClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= githubDownloadMaxRedirects {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" || req.URL.Host == "" {
				return permanent(errors.New("download redirected to a non-https URL"))
			}
			req.Header.Del("Referer")
			return nil
		},
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// DownloadSBOM exports the dependency-graph SBOM of repo ("owner/name")
// through GitHub's asynchronous SBOM API and writes the SPDX JSON document to
// outputFile.
//
// The synchronous GET /repos/{owner}/{repo}/dependency-graph/sbom endpoint
// generated the document inline under a hard server-side timeout, which large
// repositories (tens of thousands of packages) exceed deterministically, and
// GitHub removes it on 2026-11-13. The replacement is a three-step flow:
//
//  1. GET .../dependency-graph/sbom/generate-report -> 201 {"sbom_url": ...}
//  2. GET sbom_url (.../fetch-report/{uuid}) -> 202 while GitHub is still
//     working (with Retry-After), 302 to a temporary download URL when done
//  3. GET the download URL, without the GitHub token
//
// Transient failures (network errors, 5xx, an expired report) restart the
// whole sequence up to maxAttempts times; permanent ones (401/403/404, an
// unexpected sbom_url host, poll deadline exceeded) fail immediately.
func (g *GitHubClient) DownloadSBOM(ctx context.Context, repo, outputFile string) error {
	logger.Info("Downloading SBOM from %s", repo)

	var lastErr error
	for attempt := 1; attempt <= g.maxAttempts; attempt++ {
		logger.Info("Starting SBOM export, attempt %d/%d", attempt, g.maxAttempts)

		body, err := g.export(ctx, repo)
		if err == nil {
			// #nosec G703 -- outputFile is a controlled internal temp path from main.go
			if err := os.WriteFile(outputFile, body, 0644); err != nil {
				return fmt.Errorf("failed to write SBOM to file: %w", err)
			}
			logger.Success("SBOM downloaded successfully (%d bytes) on attempt %d", len(body), attempt)
			return nil
		}

		if isPermanent(err) || ctx.Err() != nil {
			return err
		}
		lastErr = err
		if attempt < g.maxAttempts {
			delay := g.retryDelay * time.Duration(attempt)
			logger.Warning("SBOM export attempt %d failed: %v", attempt, err)
			logger.Info("Waiting %v before retry...", delay)
			if err := g.sleep(ctx, delay); err != nil {
				return err
			}
		}
	}

	return fmt.Errorf("failed to download SBOM after %d attempts: %w", g.maxAttempts, lastErr)
}

// export runs one request -> poll -> download cycle and returns the SBOM bytes.
func (g *GitHubClient) export(ctx context.Context, repo string) ([]byte, error) {
	reportURL, err := g.requestGeneration(ctx, repo)
	if err != nil {
		return nil, err
	}

	downloadURL, inline, err := g.waitForReport(ctx, reportURL)
	if err != nil {
		return nil, err
	}
	if inline != nil {
		return inline, nil
	}

	return g.downloadReport(ctx, downloadURL)
}

// requestGeneration asks GitHub to start generating the SBOM and returns the
// fetch-report URL to poll.
func (g *GitHubClient) requestGeneration(ctx context.Context, repo string) (string, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/dependency-graph/sbom/generate-report", g.baseURL, repo)

	resp, body, err := g.callAPI(ctx, endpoint)
	if err != nil {
		return "", err
	}
	if err := classifyAPIStatus(resp, body, "SBOM generation request"); err != nil {
		return "", err
	}

	var out struct {
		SBOMURL string `json:"sbom_url"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.SBOMURL == "" {
		return "", fmt.Errorf("SBOM generation request returned no sbom_url (status %d): %s",
			resp.StatusCode, snippet(body))
	}
	if err := g.checkSameAPIHost(out.SBOMURL); err != nil {
		return "", err
	}

	logger.Info("GitHub accepted the SBOM generation request; waiting for the report")
	return out.SBOMURL, nil
}

type pollState int

const (
	pollPending pollState = iota
	pollReady
	pollInline
)

type pollResult struct {
	state       pollState
	downloadURL string
	body        []byte
	retryAfter  time.Duration
}

// waitForReport polls reportURL until GitHub redirects to the generated
// document. It returns the pre-signed download URL, or the document itself
// when GitHub serves it inline.
func (g *GitHubClient) waitForReport(ctx context.Context, reportURL string) (string, []byte, error) {
	start := g.now()
	deadline := start.Add(g.maxWait)
	interval := g.minPoll
	failures := 0

	for {
		res, err := g.pollOnce(ctx, reportURL)
		switch {
		case err == nil && res.state == pollReady:
			logger.Success("SBOM report is ready (waited %v)", g.now().Sub(start).Round(time.Second))
			return res.downloadURL, nil, nil
		case err == nil && res.state == pollInline:
			logger.Success("SBOM report is ready (waited %v)", g.now().Sub(start).Round(time.Second))
			return "", res.body, nil
		case err == nil:
			failures = 0
		case ctx.Err() != nil, isPermanent(err), errors.Is(err, errReportFailed):
			return "", nil, err
		default:
			failures++
			if failures >= githubSBOMMaxPollErrors {
				return "", nil, fmt.Errorf("polling the SBOM report failed %d times in a row: %w", failures, err)
			}
			logger.Warning("Polling the SBOM report failed (%d/%d): %v", failures, githubSBOMMaxPollErrors, err)
		}

		remaining := deadline.Sub(g.now())
		if remaining <= 0 {
			return "", nil, permanent(fmt.Errorf("GitHub did not finish generating the SBOM within %v", g.maxWait))
		}
		wait := g.pollDelay(interval, res.retryAfter, remaining)
		logger.Info("SBOM report not ready yet (elapsed %v); checking again in %v",
			g.now().Sub(start).Round(time.Second), wait)
		if err := g.sleep(ctx, wait); err != nil {
			return "", nil, err
		}
		interval *= 2
		if interval > g.maxPoll {
			interval = g.maxPoll
		}
	}
}

// pollDelay picks the next poll spacing: the larger of our own back-off and
// GitHub's Retry-After, clamped to [minPoll, maxPoll] and to the time left
// before the deadline.
func (g *GitHubClient) pollDelay(interval, retryAfter, remaining time.Duration) time.Duration {
	wait := interval
	if retryAfter > wait {
		wait = retryAfter
	}
	if wait > g.maxPoll {
		wait = g.maxPoll
	}
	if wait < g.minPoll {
		wait = g.minPoll
	}
	if wait > remaining {
		wait = remaining
	}
	return wait
}

// pollOnce performs a single fetch-report call and interprets the response.
func (g *GitHubClient) pollOnce(ctx context.Context, reportURL string) (pollResult, error) {
	resp, body, err := g.callAPI(ctx, reportURL)
	if err != nil {
		return pollResult{}, err
	}
	retryAfter := g.parseRetryAfter(resp.Header.Get("Retry-After"))

	switch {
	case resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusCreated:
		// Still generating. The docs say 202; the launch changelog said 201.
		return pollResult{state: pollPending, retryAfter: retryAfter}, nil

	case resp.StatusCode == http.StatusOK:
		return classifyInlineReport(body, retryAfter)

	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		loc := resp.Header.Get("Location")
		if u, err := url.Parse(loc); err != nil || u.Scheme != "https" || u.Host == "" {
			return pollResult{}, permanent(errors.New("SBOM report redirected to a download URL that is missing or not https"))
		}
		return pollResult{state: pollReady, downloadURL: loc}, nil

	case resp.StatusCode == http.StatusNotFound:
		// Reports are retained for a limited time; an unknown UUID means
		// GitHub dropped this one.
		return pollResult{}, fmt.Errorf("%w: status 404 (report expired or unknown)", errReportFailed)
	}

	// 429, 5xx and hard 4xx. Retry-After travels with the error so the poll
	// loop honours it if it decides to try again.
	return pollResult{retryAfter: retryAfter}, classifyAPIStatus(resp, body, "SBOM report poll")
}

// classifyInlineReport interprets a 200 from fetch-report. The documented
// answers are 202 and 302, so this is defensive: accept a body that really is
// an SBOM, treat an empty object (the 202 body) as still pending, and turn a
// GitHub error envelope into an error instead of writing it out as the
// document.
func classifyInlineReport(body []byte, retryAfter time.Duration) (pollResult, error) {
	var probe struct {
		Message     string          `json:"message"`
		SPDXVersion string          `json:"spdxVersion"`
		SPDXID      string          `json:"SPDXID"`
		BOMFormat   string          `json:"bomFormat"`
		SBOM        json.RawMessage `json:"sbom"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return pollResult{retryAfter: retryAfter}, errors.New("SBOM report answered 200 with a body that is not a JSON object")
	}
	switch {
	case probe.Message != "" && isRetryableError(probe.Message):
		return pollResult{}, fmt.Errorf("%w: GitHub reported %q", errReportFailed, probe.Message)
	case probe.Message != "":
		return pollResult{}, permanent(fmt.Errorf("SBOM report poll: GitHub answered 200 with an error: %s", probe.Message))
	case probe.SPDXVersion != "" || probe.SPDXID != "" || probe.BOMFormat != "" || len(probe.SBOM) > 0:
		return pollResult{state: pollInline, body: body}, nil
	case isEmptyJSONObject(body):
		return pollResult{state: pollPending, retryAfter: retryAfter}, nil
	}
	return pollResult{retryAfter: retryAfter}, errors.New("SBOM report answered 200 with a body that is not an SBOM")
}

func isEmptyJSONObject(body []byte) bool {
	var m map[string]json.RawMessage
	return json.Unmarshal(body, &m) == nil && len(m) == 0
}

// parseRetryAfter reads a Retry-After header in either delay-seconds or
// HTTP-date form. Anything unparsable yields 0 so the caller's own back-off
// applies.
func (g *GitHubClient) parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(g.now()); d > 0 {
			return d
		}
	}
	return 0
}

// downloadReport fetches the generated document from the pre-signed URL. The
// URL embeds its own credentials, so the request must not carry the GitHub
// token (the storage service answers 401 if it does), and the URL itself is
// never logged or quoted in errors; only its host is.
func (g *GitHubClient) downloadReport(ctx context.Context, downloadURL string) ([]byte, error) {
	host := "the download host"
	if u, err := url.Parse(downloadURL); err == nil && u.Host != "" {
		host = u.Host
	}
	logger.Info("Downloading the generated SBOM from %s", host)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, permanent(fmt.Errorf("failed to create download request for %s", host))
	}

	resp, err := g.downloadClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SBOM download from %s failed: %w", host, stripURL(err))
	}
	body, err := readBody(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM download from %s: %w", host, stripURL(err))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SBOM download from %s failed (status %d)", host, resp.StatusCode)
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("SBOM downloaded from %s is not valid JSON (%d bytes)", host, len(body))
	}
	return body, nil
}

// callAPI performs an authenticated GET against the REST API and returns the
// response with its body already read and closed.
func (g *GitHubClient) callAPI(ctx context.Context, endpoint string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, permanent(fmt.Errorf("failed to create request: %w", err))
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}

	resp, err := g.apiClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request to GitHub failed: %w", err)
	}
	body, err := readBody(resp)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read GitHub response: %w", err)
	}
	return resp, body, nil
}

// checkSameAPIHost refuses to poll an sbom_url on any host other than the API
// we were configured for, since polls carry the bearer token.
func (g *GitHubClient) checkSameAPIHost(raw string) error {
	base, err := url.Parse(g.baseURL)
	if err != nil {
		return permanent(fmt.Errorf("invalid GitHub API base URL %q: %w", g.baseURL, err))
	}
	u, err := url.Parse(raw)
	if err != nil {
		return permanent(errors.New("GitHub returned an unparsable sbom_url"))
	}
	if u.Scheme != base.Scheme || u.Host != base.Host {
		return permanent(fmt.Errorf("GitHub returned an sbom_url on an unexpected host (%s); refusing to send credentials there", u.Host))
	}
	return nil
}

// classifyAPIStatus turns a REST response into an error unless it is a clean
// success, marking the ones a retry cannot fix as permanent. what names the
// call for the message.
func classifyAPIStatus(resp *http.Response, body []byte, what string) error {
	code := resp.StatusCode
	switch {
	case code >= 200 && code < 300:
		// The deprecated synchronous endpoint could answer 200 with an error
		// message in the body; keep recognising that shape.
		if msg, ok := retryableGitHubMessage(body); ok {
			return fmt.Errorf("%s: GitHub reported a transient error: %s", what, msg)
		}
		return nil
	case code >= 300 && code < 400:
		return permanent(fmt.Errorf("%s: GitHub redirected (status %d) to %s; the repository may have been renamed, update `repository`",
			what, code, redactURL(resp.Header.Get("Location"))))
	case code == http.StatusTooManyRequests || code >= 500:
		return fmt.Errorf("%s: GitHub API error (status %d): %s", what, code, snippet(body))
	}
	if msg, ok := retryableGitHubMessage(body); ok {
		return fmt.Errorf("%s: GitHub API error (status %d): %s", what, code, msg)
	}
	return permanent(fmt.Errorf("%s: GitHub API error (status %d): %s%s", what, code, snippet(body), statusHint(code)))
}

// statusHint adds the usual cause of a hard 4xx from the SBOM endpoints.
func statusHint(code int) string {
	switch code {
	case http.StatusUnauthorized:
		return " (check github-token)"
	case http.StatusForbidden:
		return " (the token lacks access to the repository, or the dependency_sbom rate limit is exhausted)"
	case http.StatusNotFound:
		return " (check that the repository exists, the token can read its contents, and the dependency graph is enabled)"
	}
	return ""
}

// redactURL keeps only scheme, host and path of raw, dropping query, fragment
// and userinfo, so a URL can be named in a message without any credentials it
// carries.
func redactURL(raw string) string {
	if raw == "" {
		return "(no Location header)"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(unparsable Location)"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// stripURL unwraps *url.Error so the URL it quotes (which for downloads is
// pre-signed) never reaches logs or error output.
func stripURL(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}

func readBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if closeErr := resp.Body.Close(); closeErr != nil {
		logger.Warning("Failed to close response body: %v", closeErr)
	}
	return body, err
}

// snippet trims an error response body for inclusion in an error message.
func snippet(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > githubErrorSnippetLen {
		s = s[:githubErrorSnippetLen] + "..."
	}
	return s
}

// retryableGitHubMessage inspects a response body for a JSON `.message` field
// matching a known transient error pattern. Returns the message and whether
// it should trigger a retry.
func retryableGitHubMessage(body []byte) (string, bool) {
	var probe struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "", false
	}
	if probe.Message == "" {
		return "", false
	}
	return probe.Message, isRetryableError(probe.Message)
}

func isRetryableError(message string) bool {
	retryableMessages := []string{
		"Request timed out",
		"Failed to generate SBOM",
		"timeout",
	}
	for _, msg := range retryableMessages {
		if strings.Contains(message, msg) {
			return true
		}
	}
	return false
}
