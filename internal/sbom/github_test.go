package sbom

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	stubRepo      = "acme/widgets"
	stubGenPath   = "/repos/acme/widgets/dependency-graph/sbom/generate-report"
	stubFetchPath = "/repos/acme/widgets/dependency-graph/sbom/fetch-report/11915fac-e109-4e49-985d-661c0b7729cf"
	stubBlobPath  = "/blob/11915fac"
	stubBlobQuery = "?sig=SECRET-SAS-TOKEN"
	stubSBOM      = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"com.github.acme/widgets","packages":[{"name":"rails","versionInfo":"7.1.0"}]}`
)

// githubStub fakes the hosts involved in an export: the REST API
// (generate-report and fetch-report) and the storage host serving the
// pre-signed download. Handlers are swappable per test and receive the
// 1-based call number for that path; counters and header captures are
// mutex-guarded for -race.
type githubStub struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	genN     int
	fetchN   int
	blobN    int
	apiAuth  []string // Authorization header on every API call
	apiVers  []string // X-GitHub-Api-Version on every API call
	blobAuth []string // Authorization header on every download call

	generate func(n int, w http.ResponseWriter)
	fetch    func(n int, w http.ResponseWriter)
	blob     func(n int, w http.ResponseWriter)
}

func newGitHubStub(t *testing.T) *githubStub {
	s := &githubStub{t: t}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)

	// Defaults: accept immediately, report ready on the first poll, serve the
	// document from the blob path.
	s.generate = func(_ int, w http.ResponseWriter) { s.writeAccepted(w) }
	s.fetch = func(_ int, w http.ResponseWriter) { s.redirectToBlob(w) }
	s.blob = func(_ int, w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(stubSBOM))
	}
	return s
}

func (s *githubStub) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch r.URL.Path {
	case stubGenPath:
		s.genN++
		s.apiAuth = append(s.apiAuth, r.Header.Get("Authorization"))
		s.apiVers = append(s.apiVers, r.Header.Get("X-GitHub-Api-Version"))
		s.generate(s.genN, w)
	case stubFetchPath:
		s.fetchN++
		s.apiAuth = append(s.apiAuth, r.Header.Get("Authorization"))
		s.apiVers = append(s.apiVers, r.Header.Get("X-GitHub-Api-Version"))
		s.fetch(s.fetchN, w)
	case stubBlobPath:
		s.blobN++
		s.blobAuth = append(s.blobAuth, r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") != "" {
			// Azure Blob Storage rejects pre-signed requests that also carry a
			// bearer token.
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		s.blob(s.blobN, w)
	default:
		s.t.Errorf("unexpected request to %s", r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	}
}

func (s *githubStub) writeAccepted(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"sbom_url":%q}`, s.srv.URL+stubFetchPath)
}

func (s *githubStub) writePending(w http.ResponseWriter, retryAfter string) {
	if retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("{}"))
}

func (s *githubStub) redirectToBlob(w http.ResponseWriter) {
	w.Header().Set("Location", s.srv.URL+stubBlobPath+stubBlobQuery)
	w.WriteHeader(http.StatusFound)
}

func (s *githubStub) counts() (gen, fetch, blob int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.genN, s.fetchN, s.blobN
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"message":%q,"documentation_url":"https://docs.github.com/rest","status":"%d"}`, msg, code)
}

// testClock replaces real waiting: sleep records the requested duration and
// advances the clock the client reads through now().
type testClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func (c *testClock) at() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) recorded() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.sleeps...)
}

func newTestClient(t *testing.T, s *githubStub, token string) (*GitHubClient, *testClock) {
	t.Helper()
	clk := &testClock{now: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}

	c := NewGitHubClient(token)
	c.baseURL = s.srv.URL
	c.apiClient = newGitHubAPIClient(s.srv.Client().Transport)
	c.downloadClient = newGitHubDownloadClient(s.srv.Client().Transport)
	c.retryDelay = time.Second
	c.now = clk.at
	c.sleep = func(ctx context.Context, d time.Duration) error {
		clk.mu.Lock()
		clk.sleeps = append(clk.sleeps, d)
		clk.now = clk.now.Add(d)
		clk.mu.Unlock()
		return ctx.Err()
	}
	return c, clk
}

func download(t *testing.T, c *GitHubClient) (string, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "sbom.json")
	return out, c.DownloadSBOM(context.Background(), stubRepo, out)
}

func assertCalls(t *testing.T, s *githubStub, gen, fetch, blob int) {
	t.Helper()
	g, f, b := s.counts()
	if g != gen || f != fetch || b != blob {
		t.Errorf("calls generate=%d fetch=%d download=%d, want %d/%d/%d", g, f, b, gen, fetch, blob)
	}
}

func assertSleeps(t *testing.T, clk *testClock, want ...time.Duration) {
	t.Helper()
	got := clk.recorded()
	if len(got) != len(want) {
		t.Fatalf("sleeps = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sleep #%d = %v, want %v (all: %v)", i+1, got[i], want[i], got)
		}
	}
}

func assertFileIs(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("written file = %s, want %s", got, want)
	}
}

func TestDownloadSBOM_AsyncFlow(t *testing.T) {
	s := newGitHubStub(t)
	s.fetch = func(n int, w http.ResponseWriter) {
		if n <= 2 {
			s.writePending(w, "1")
			return
		}
		s.redirectToBlob(w)
	}
	c, clk := newTestClient(t, s, "test-token")

	out, err := download(t, c)
	if err != nil {
		t.Fatalf("DownloadSBOM: %v", err)
	}
	assertFileIs(t, out, stubSBOM)
	assertCalls(t, s, 1, 3, 1)

	for _, a := range s.apiAuth {
		if a != "Bearer test-token" {
			t.Errorf("API call Authorization = %q, want the bearer token", a)
		}
	}
	for _, v := range s.apiVers {
		if v != githubAPIVersion {
			t.Errorf("X-GitHub-Api-Version = %q, want %q", v, githubAPIVersion)
		}
	}
	for _, a := range s.blobAuth {
		if a != "" {
			t.Errorf("GitHub token leaked to the download host: %q", a)
		}
	}
	// Retry-After: 1 is below the floor, so the client's own back-off applies.
	assertSleeps(t, clk, 2*time.Second, 4*time.Second)
}

func TestDownloadSBOM_HonoursRetryAfter(t *testing.T) {
	s := newGitHubStub(t)
	s.fetch = func(n int, w http.ResponseWriter) {
		switch n {
		case 1:
			s.writePending(w, "7")
		case 2:
			s.writePending(w, "600")
		default:
			s.redirectToBlob(w)
		}
	}
	c, clk := newTestClient(t, s, "test-token")

	if _, err := download(t, c); err != nil {
		t.Fatalf("DownloadSBOM: %v", err)
	}
	assertSleeps(t, clk, 7*time.Second, githubSBOMMaxPollInterval)
}

func TestDownloadSBOM_RetryAfterHTTPDate(t *testing.T) {
	s := newGitHubStub(t)
	c, clk := newTestClient(t, s, "test-token")
	s.fetch = func(n int, w http.ResponseWriter) {
		if n == 1 {
			s.writePending(w, clk.at().Add(9*time.Second).UTC().Format(http.TimeFormat))
			return
		}
		s.redirectToBlob(w)
	}

	if _, err := download(t, c); err != nil {
		t.Fatalf("DownloadSBOM: %v", err)
	}
	assertSleeps(t, clk, 9*time.Second)
}

func TestDownloadSBOM_RetriesTransientGenerationFailure(t *testing.T) {
	s := newGitHubStub(t)
	s.generate = func(n int, w http.ResponseWriter) {
		if n <= 2 {
			writeJSONError(w, http.StatusBadGateway, "Server Error")
			return
		}
		s.writeAccepted(w)
	}
	c, clk := newTestClient(t, s, "test-token")

	out, err := download(t, c)
	if err != nil {
		t.Fatalf("DownloadSBOM: %v", err)
	}
	assertFileIs(t, out, stubSBOM)
	assertCalls(t, s, 3, 1, 1)
	// The back-off between attempts scales with the attempt number.
	assertSleeps(t, clk, time.Second, 2*time.Second)
}

func TestDownloadSBOM_RetriesTransientMessageInSuccessStatus(t *testing.T) {
	s := newGitHubStub(t)
	s.generate = func(n int, w http.ResponseWriter) {
		if n == 1 {
			writeJSONError(w, http.StatusOK, "Failed to generate SBOM: Request timed out.")
			return
		}
		s.writeAccepted(w)
	}
	c, _ := newTestClient(t, s, "test-token")

	if _, err := download(t, c); err != nil {
		t.Fatalf("DownloadSBOM: %v", err)
	}
	assertCalls(t, s, 2, 1, 1)
}

func TestDownloadSBOM_PermanentErrorsDoNotRetry(t *testing.T) {
	cases := []struct {
		code      int
		msg, hint string
	}{
		{http.StatusUnauthorized, "Bad credentials", "github-token"},
		{http.StatusForbidden, "Resource not accessible by integration", "lacks access"},
		{http.StatusNotFound, "Not Found", "dependency graph is enabled"},
		{http.StatusUnprocessableEntity, "Validation Failed", ""},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			s := newGitHubStub(t)
			s.generate = func(_ int, w http.ResponseWriter) { writeJSONError(w, tc.code, tc.msg) }
			c, clk := newTestClient(t, s, "test-token")

			_, err := download(t, c)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !isPermanent(err) {
				t.Errorf("error should be permanent: %v", err)
			}
			for _, want := range []string{fmt.Sprintf("status %d", tc.code), tc.msg, tc.hint} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q should mention %q", err, want)
				}
			}
			assertCalls(t, s, 1, 0, 0)
			assertSleeps(t, clk)
		})
	}
}

func TestDownloadSBOM_RenamedRepositoryHint(t *testing.T) {
	s := newGitHubStub(t)
	s.generate = func(_ int, w http.ResponseWriter) {
		w.Header().Set("Location", s.srv.URL+"/repos/acme/gadgets/dependency-graph/sbom/generate-report?sig=SECRET-QUERY")
		w.WriteHeader(http.StatusMovedPermanently)
	}
	c, _ := newTestClient(t, s, "test-token")

	_, err := download(t, c)
	if err == nil || !isPermanent(err) || !strings.Contains(err.Error(), "renamed") {
		t.Fatalf("expected a permanent error mentioning a rename, got %v", err)
	}
	// The redirect target is named, but only scheme, host and path of it.
	if !strings.Contains(err.Error(), "/repos/acme/gadgets/") || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("error should name the redacted Location, got %q", err)
	}
	assertCalls(t, s, 1, 0, 0)
}

func TestDownloadSBOM_ExpiredReportRequestsANewOne(t *testing.T) {
	s := newGitHubStub(t)
	s.fetch = func(n int, w http.ResponseWriter) {
		if n == 1 {
			writeJSONError(w, http.StatusNotFound, "Not Found")
			return
		}
		s.redirectToBlob(w)
	}
	c, clk := newTestClient(t, s, "test-token")

	if _, err := download(t, c); err != nil {
		t.Fatalf("DownloadSBOM: %v", err)
	}
	assertCalls(t, s, 2, 2, 1)
	assertSleeps(t, clk, time.Second)
}

func TestDownloadSBOM_AcceptsInlineDocument(t *testing.T) {
	s := newGitHubStub(t)
	s.fetch = func(_ int, w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(stubSBOM))
	}
	c, _ := newTestClient(t, s, "test-token")

	out, err := download(t, c)
	if err != nil {
		t.Fatalf("DownloadSBOM: %v", err)
	}
	assertFileIs(t, out, stubSBOM)
	assertCalls(t, s, 1, 1, 0)
}

func TestDownloadSBOM_InlineFailureMessageRequestsANewOne(t *testing.T) {
	s := newGitHubStub(t)
	s.fetch = func(n int, w http.ResponseWriter) {
		if n == 1 {
			writeJSONError(w, http.StatusOK, "Failed to generate SBOM")
			return
		}
		s.redirectToBlob(w)
	}
	c, _ := newTestClient(t, s, "test-token")

	if _, err := download(t, c); err != nil {
		t.Fatalf("DownloadSBOM: %v", err)
	}
	assertCalls(t, s, 2, 2, 1)
}

func TestDownloadSBOM_PollDeadlineIsPermanent(t *testing.T) {
	s := newGitHubStub(t)
	s.fetch = func(_ int, w http.ResponseWriter) { s.writePending(w, "1") }
	c, clk := newTestClient(t, s, "test-token")
	c.maxWait = 10 * time.Second

	_, err := download(t, c)
	if err == nil || !isPermanent(err) || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("expected a permanent deadline error, got %v", err)
	}
	// 2s + 4s + (8s clamped to the 4s left) lands exactly on the deadline;
	// the poll made there is the last one and no new report is requested.
	assertCalls(t, s, 1, 4, 0)
	assertSleeps(t, clk, 2*time.Second, 4*time.Second, 4*time.Second)
}

func TestDownloadSBOM_ToleratesIntermittentPollErrors(t *testing.T) {
	s := newGitHubStub(t)
	s.fetch = func(n int, w http.ResponseWriter) {
		if n <= 2 {
			writeJSONError(w, http.StatusServiceUnavailable, "Service Unavailable")
			return
		}
		s.redirectToBlob(w)
	}
	c, clk := newTestClient(t, s, "test-token")

	if _, err := download(t, c); err != nil {
		t.Fatalf("DownloadSBOM: %v", err)
	}
	assertCalls(t, s, 1, 3, 1)
	// Failed polls still wait, with the same doubling back-off as pending ones.
	assertSleeps(t, clk, 2*time.Second, 4*time.Second)
}

func TestDownloadSBOM_HonoursRetryAfterOnPollErrors(t *testing.T) {
	s := newGitHubStub(t)
	s.fetch = func(n int, w http.ResponseWriter) {
		if n <= 2 {
			w.Header().Set("Retry-After", "20")
			writeJSONError(w, http.StatusServiceUnavailable, "Service Unavailable")
			return
		}
		s.redirectToBlob(w)
	}
	c, clk := newTestClient(t, s, "test-token")

	if _, err := download(t, c); err != nil {
		t.Fatalf("DownloadSBOM: %v", err)
	}
	assertCalls(t, s, 1, 3, 1)
	assertSleeps(t, clk, 20*time.Second, 20*time.Second)
}

func TestDownloadSBOM_PollErrorCountResetsOnProgress(t *testing.T) {
	s := newGitHubStub(t)
	s.fetch = func(n int, w http.ResponseWriter) {
		switch n {
		case 5:
			s.writePending(w, "1")
		case 10:
			s.redirectToBlob(w)
		default:
			writeJSONError(w, http.StatusServiceUnavailable, "Service Unavailable")
		}
	}
	c, clk := newTestClient(t, s, "test-token")

	if _, err := download(t, c); err != nil {
		t.Fatalf("DownloadSBOM: %v", err)
	}
	// Eight errors in total but never five in a row, so the same report is
	// kept and no new one is requested: generate == 1 is the load-bearing
	// assertion here.
	assertCalls(t, s, 1, 10, 1)
	// The back-off keeps growing across errors and the pending poll alike.
	assertSleeps(t, clk, 2*time.Second, 4*time.Second, 8*time.Second, 16*time.Second,
		30*time.Second, 30*time.Second, 30*time.Second, 30*time.Second, 30*time.Second)
}

func TestDownloadSBOM_PermanentPollErrorDoesNotRetry(t *testing.T) {
	cases := []struct {
		code      int
		msg, hint string
	}{
		{http.StatusUnauthorized, "Bad credentials", "github-token"},
		{http.StatusForbidden, "Resource not accessible by integration", "lacks access"},
		{http.StatusUnprocessableEntity, "Validation Failed", ""},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			s := newGitHubStub(t)
			s.fetch = func(_ int, w http.ResponseWriter) { writeJSONError(w, tc.code, tc.msg) }
			c, clk := newTestClient(t, s, "test-token")

			_, err := download(t, c)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !isPermanent(err) {
				t.Errorf("error should be permanent: %v", err)
			}
			for _, want := range []string{"SBOM report poll", fmt.Sprintf("status %d", tc.code), tc.msg, tc.hint} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q should mention %q", err, want)
				}
			}
			assertCalls(t, s, 1, 1, 0)
			assertSleeps(t, clk)
		})
	}
}

func TestDownloadSBOM_AbandonsReportAfterRepeatedPollErrors(t *testing.T) {
	s := newGitHubStub(t)
	s.fetch = func(_ int, w http.ResponseWriter) { writeJSONError(w, http.StatusInternalServerError, "Server Error") }
	c, clk := newTestClient(t, s, "test-token")
	c.maxAttempts = 2

	_, err := download(t, c)
	if err == nil || isPermanent(err) {
		t.Fatalf("expected a transient failure after exhausting attempts, got %v", err)
	}
	for _, want := range []string{"after 2 attempts", "times in a row", "status 500"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
	assertCalls(t, s, 2, 2*githubSBOMMaxPollErrors, 0)
	// Four poll waits per attempt, the attempt back-off in between, and the
	// poll back-off starts over with the new report.
	assertSleeps(t, clk, 2*time.Second, 4*time.Second, 8*time.Second, 16*time.Second,
		time.Second,
		2*time.Second, 4*time.Second, 8*time.Second, 16*time.Second)
}

func TestDownloadSBOM_RefusesForeignSBOMURL(t *testing.T) {
	var foreignCalls atomic.Int32
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		foreignCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(foreign.Close)

	s := newGitHubStub(t)
	s.generate = func(_ int, w http.ResponseWriter) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"sbom_url":%q}`, foreign.URL+stubFetchPath)
	}
	c, _ := newTestClient(t, s, "test-token")

	_, err := download(t, c)
	if err == nil || !isPermanent(err) || !strings.Contains(err.Error(), "unexpected host") {
		t.Fatalf("expected a permanent unexpected-host error, got %v", err)
	}
	if n := foreignCalls.Load(); n != 0 {
		t.Errorf("the token-carrying client contacted the foreign host %d times", n)
	}
	assertCalls(t, s, 1, 0, 0)
}

func TestDownloadSBOM_DownloadFailures(t *testing.T) {
	t.Run("transient failure retries the whole export", func(t *testing.T) {
		s := newGitHubStub(t)
		s.blob = func(n int, w http.ResponseWriter) {
			if n == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(stubSBOM))
		}
		c, _ := newTestClient(t, s, "test-token")

		out, err := download(t, c)
		if err != nil {
			t.Fatalf("DownloadSBOM: %v", err)
		}
		assertFileIs(t, out, stubSBOM)
		assertCalls(t, s, 2, 2, 2)
	})

	t.Run("invalid JSON retries the whole export", func(t *testing.T) {
		s := newGitHubStub(t)
		s.blob = func(n int, w http.ResponseWriter) {
			if n == 1 {
				_, _ = w.Write([]byte("<html>maintenance</html>"))
				return
			}
			_, _ = w.Write([]byte(stubSBOM))
		}
		c, _ := newTestClient(t, s, "test-token")

		if _, err := download(t, c); err != nil {
			t.Fatalf("DownloadSBOM: %v", err)
		}
		assertCalls(t, s, 2, 2, 2)
	})

	t.Run("errors name the host but never the pre-signed URL", func(t *testing.T) {
		s := newGitHubStub(t)
		s.blob = func(_ int, w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) }
		c, _ := newTestClient(t, s, "test-token")
		c.maxAttempts = 1

		_, err := download(t, c)
		if err == nil {
			t.Fatal("expected an error")
		}
		host := strings.TrimPrefix(s.srv.URL, "https://")
		if !strings.Contains(err.Error(), host) || !strings.Contains(err.Error(), "status 403") {
			t.Errorf("error %q should name host %s and the status", err, host)
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("error leaks the pre-signed URL: %q", err)
		}
	})

	t.Run("unreachable download host does not leak the URL", func(t *testing.T) {
		s := newGitHubStub(t)
		s.fetch = func(_ int, w http.ResponseWriter) {
			w.Header().Set("Location", "https://127.0.0.1:1"+stubBlobPath+stubBlobQuery)
			w.WriteHeader(http.StatusFound)
		}
		c, _ := newTestClient(t, s, "test-token")
		c.maxAttempts = 1

		_, err := download(t, c)
		if err == nil {
			t.Fatal("expected an error")
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("error leaks the pre-signed URL: %q", err)
		}
	})
}

func TestDownloadSBOM_ContextCancelled(t *testing.T) {
	s := newGitHubStub(t)
	c, clk := newTestClient(t, s, "test-token")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := c.DownloadSBOM(ctx, stubRepo, filepath.Join(t.TempDir(), "sbom.json"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	assertSleeps(t, clk)
}

func TestDownloadSBOM_NoTokenSendsNoAuthorization(t *testing.T) {
	s := newGitHubStub(t)
	c, _ := newTestClient(t, s, "")

	if _, err := download(t, c); err != nil {
		t.Fatalf("DownloadSBOM: %v", err)
	}
	for _, a := range s.apiAuth {
		if a != "" {
			t.Errorf("Authorization = %q, want none for an empty token", a)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	c := NewGitHubClient("")
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }

	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"1", time.Second},
		{" 15 ", 15 * time.Second},
		{"0", 0},
		{"-3", 0},
		{"soon", 0},
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0},
	}
	for _, tc := range cases {
		if got := c.parseRetryAfter(tc.in); got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

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

func TestDownloadSBOM_UndocumentedInlineResponses(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		maxWait   time.Duration
		permanent bool
		want      string
		calls     [3]int
	}{
		{"error envelope is permanent", `{"message":"Not Found","status":"200"}`, 0, true, "Not Found", [3]int{1, 1, 0}},
		{"empty object counts as pending", `{}`, 10 * time.Second, true, "did not finish", [3]int{1, 4, 0}},
		{"non-SBOM object is a poll failure", `{"unexpected":"shape"}`, 0, false, "not an SBOM", [3]int{1, githubSBOMMaxPollErrors, 0}},
		{"JSON array is a poll failure", `[1,2,3]`, 0, false, "not a JSON object", [3]int{1, githubSBOMMaxPollErrors, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newGitHubStub(t)
			s.fetch = func(_ int, w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, _ = w.Write([]byte(tc.body))
			}
			c, _ := newTestClient(t, s, "test-token")
			c.maxAttempts = 1
			if tc.maxWait > 0 {
				c.maxWait = tc.maxWait
			}

			_, err := download(t, c)
			if err == nil {
				t.Fatal("expected an error")
			}
			if isPermanent(err) != tc.permanent {
				t.Errorf("isPermanent = %v, want %v: %v", isPermanent(err), tc.permanent, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should mention %q", err, tc.want)
			}
			assertCalls(t, s, tc.calls[0], tc.calls[1], tc.calls[2])
		})
	}
}

func TestDownloadSBOM_GenerateWithoutSBOMURLIsTransient(t *testing.T) {
	for _, body := range []string{`{"unexpected":"shape"}`, `{"sbom_url":""}`, `<html>oops</html>`} {
		t.Run(body, func(t *testing.T) {
			s := newGitHubStub(t)
			s.generate = func(_ int, w http.ResponseWriter) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(body))
			}
			c, clk := newTestClient(t, s, "test-token")

			_, err := download(t, c)
			if err == nil || isPermanent(err) {
				t.Fatalf("expected a transient error, got %v", err)
			}
			for _, want := range []string{"no sbom_url", "after 3 attempts"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q should mention %q", err, want)
				}
			}
			assertCalls(t, s, 3, 0, 0)
			assertSleeps(t, clk, time.Second, 2*time.Second)
		})
	}
}

func TestDownloadSBOM_RefusesUnsafeDownloadURL(t *testing.T) {
	cases := map[string]func(s *githubStub, w http.ResponseWriter){
		"plain http": func(s *githubStub, w http.ResponseWriter) {
			w.Header().Set("Location", "http://"+strings.TrimPrefix(s.srv.URL, "https://")+stubBlobPath+stubBlobQuery)
			w.WriteHeader(http.StatusFound)
		},
		"missing Location": func(_ *githubStub, w http.ResponseWriter) {
			w.WriteHeader(http.StatusFound)
		},
	}
	for name, redirect := range cases {
		t.Run(name, func(t *testing.T) {
			s := newGitHubStub(t)
			s.fetch = func(_ int, w http.ResponseWriter) { redirect(s, w) }
			c, clk := newTestClient(t, s, "test-token")

			_, err := download(t, c)
			if err == nil || !isPermanent(err) || !strings.Contains(err.Error(), "not https") {
				t.Fatalf("expected a permanent not-https error, got %v", err)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Errorf("error leaks the URL: %q", err)
			}
			assertCalls(t, s, 1, 1, 0)
			assertSleeps(t, clk)
		})
	}
}

func TestDownloadSBOM_DownloadRedirects(t *testing.T) {
	t.Run("https hop is followed without Referer or token", func(t *testing.T) {
		var mu sync.Mutex
		var hits int
		var referer, auth string
		final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits++
			referer, auth = r.Header.Get("Referer"), r.Header.Get("Authorization")
			mu.Unlock()
			_, _ = w.Write([]byte(stubSBOM))
		}))
		t.Cleanup(final.Close)

		s := newGitHubStub(t)
		s.blob = func(_ int, w http.ResponseWriter) {
			w.Header().Set("Location", final.URL+"/final?sig=SECOND-SECRET")
			w.WriteHeader(http.StatusFound)
		}
		c, _ := newTestClient(t, s, "test-token")

		out, err := download(t, c)
		if err != nil {
			t.Fatalf("DownloadSBOM: %v", err)
		}
		assertFileIs(t, out, stubSBOM)
		mu.Lock()
		defer mu.Unlock()
		if hits != 1 || referer != "" || auth != "" {
			t.Errorf("final host saw hits=%d Referer=%q Authorization=%q; want 1 hit with neither header", hits, referer, auth)
		}
	})

	t.Run("plain-http hop is refused before it is contacted", func(t *testing.T) {
		var hits atomic.Int32
		plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			_, _ = w.Write([]byte(stubSBOM))
		}))
		t.Cleanup(plain.Close)

		s := newGitHubStub(t)
		s.blob = func(_ int, w http.ResponseWriter) {
			w.Header().Set("Location", plain.URL+"/final?sig=PLAIN-SECRET")
			w.WriteHeader(http.StatusFound)
		}
		c, clk := newTestClient(t, s, "test-token")

		_, err := download(t, c)
		if err == nil || !isPermanent(err) || !strings.Contains(err.Error(), "non-https") {
			t.Fatalf("expected a permanent non-https error, got %v", err)
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("error leaks the pre-signed URL: %q", err)
		}
		if n := hits.Load(); n != 0 {
			t.Errorf("plain-http host was contacted %d times", n)
		}
		assertCalls(t, s, 1, 1, 1)
		assertSleeps(t, clk)
	})

	t.Run("redirect loops are cut off", func(t *testing.T) {
		s := newGitHubStub(t)
		s.blob = func(n int, w http.ResponseWriter) {
			w.Header().Set("Location", fmt.Sprintf("%s%s?hop=%d", s.srv.URL, stubBlobPath, n))
			w.WriteHeader(http.StatusFound)
		}
		c, _ := newTestClient(t, s, "test-token")
		c.maxAttempts = 1

		_, err := download(t, c)
		if err == nil || isPermanent(err) || !strings.Contains(err.Error(), "too many redirects") {
			t.Fatalf("expected a transient too-many-redirects error, got %v", err)
		}
		assertCalls(t, s, 1, 1, githubDownloadMaxRedirects)
	})
}

func TestDownloadSBOM_CancelledDuringPollWait(t *testing.T) {
	s := newGitHubStub(t)
	s.fetch = func(_ int, w http.ResponseWriter) { s.writePending(w, "1") }
	c, clk := newTestClient(t, s, "test-token")
	ctx, cancel := context.WithCancel(context.Background())
	recordingSleep := c.sleep
	c.sleep = func(ctx context.Context, d time.Duration) error {
		cancel()
		return recordingSleep(ctx, d)
	}

	err := c.DownloadSBOM(ctx, stubRepo, filepath.Join(t.TempDir(), "sbom.json"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		t.Errorf("client issued another request after cancellation: %v", err)
	}
	assertCalls(t, s, 1, 1, 0)
	assertSleeps(t, clk, 2*time.Second)
}
