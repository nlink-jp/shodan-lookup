package shodan

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testKey contains characters that change under query escaping, so the scrub
// is exercised in both spellings.
const testKey = "SEKRIT+key/with=chars0123456789"

func newClient(base string, timeout time.Duration) *Client {
	c := New(base, testKey, timeout, 0, "shodan-lookup/test")
	return c
}

// assertNoKey fails if the key, raw or escaped, appears in any text a caller
// could see.
func assertNoKey(t *testing.T, where string, texts ...string) {
	t.Helper()
	for _, s := range texts {
		for _, k := range []string{testKey, "SEKRIT%2Bkey%2Fwith%3Dchars0123456789", "SEKRIT"} {
			if strings.Contains(s, k) {
				t.Errorf("%s: the key appears in %q", where, s)
			}
		}
	}
}

func clientErr(t *testing.T, err error) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v (%T) is not a *shodan.Error", err, err)
	}
	return e
}

func TestTheKeyTravelsInTheQueryAndNowhereElse(t *testing.T) {
	var gotKey, gotPath, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotPath, gotUA = r.URL.Query().Get("key"), r.URL.Path, r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(`{"ip_str":"192.0.2.10"}`))
	}))
	defer srv.Close()

	resp, err := newClient(srv.URL, time.Second).Host(context.Background(), "2001:4860:4860::8888")
	if err != nil {
		t.Fatal(err)
	}
	if gotKey != testKey {
		t.Errorf("key sent = %q", gotKey)
	}
	if gotPath != "/shodan/host/2001:4860:4860::8888" {
		t.Errorf("path = %q", gotPath)
	}
	if gotUA != "shodan-lookup/test" {
		t.Errorf("User-Agent = %q", gotUA)
	}
	assertNoKey(t, "Response.Endpoint", resp.Endpoint)
	if resp.Endpoint != "/shodan/host/2001:4860:4860::8888" {
		t.Errorf("Endpoint = %q", resp.Endpoint)
	}
}

func TestCountSendsQueryAndFacetsWithAStableEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("query") != `port:22 country:"JP"` || r.URL.Query().Get("facets") != "org:5,ip:3" {
			t.Errorf("query = %v", r.URL.Query())
		}
		_, _ = w.Write([]byte(`{"matches":[],"total":2}`))
	}))
	defer srv.Close()
	resp, err := newClient(srv.URL, time.Second).Count(context.Background(), `port:22 country:"JP"`, "org:5,ip:3")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Endpoint, "/shodan/host/count?facets=") {
		t.Errorf("Endpoint = %q (keys should be sorted, key excluded)", resp.Endpoint)
	}
	assertNoKey(t, "Count endpoint", resp.Endpoint)
}

func TestAMissingKeySendsNothing(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	_, err := New(srv.URL, "", time.Second, 0, "t").APIInfo(context.Background())
	if Code(err) != CodeMissingKey {
		t.Errorf("code = %q, want %q", Code(err), CodeMissingKey)
	}
	if hits.Load() != 0 {
		t.Error("a request went out without a key")
	}
}

// Every way an exchange can fail without an HTTP status: none may say the key.
func TestNoFailurePathQuotesTheKey(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsSrv.Close()

	for name, tc := range map[string]struct {
		base string
		code string
	}{
		"timeout":            {slow.URL, CodeTimeout},
		"connection refused": {"http://127.0.0.1:1", CodeNetwork},
		"untrusted TLS":      {tlsSrv.URL, CodeNetwork},
		"unresolvable host":  {"https://no-such-host.invalid", CodeNetwork},
	} {
		_, err := newClient(tc.base, 100*time.Millisecond).Host(context.Background(), "8.8.8.8")
		e := clientErr(t, err)
		if e.Code != tc.code {
			t.Errorf("%s: code = %q, want %q (%s)", name, e.Code, tc.code, e.Message)
		}
		assertNoKey(t, name, e.Error(), e.Message, e.APIError)
		// The first guard (no URL in a message) must hold on its own; the
		// scrub is the second line, and finding it at work here means the
		// first one failed.
		if strings.Contains(e.Message, "[redacted]") || strings.Contains(e.Message, "key=") {
			t.Errorf("%s: the request URL reached the message: %s", name, e.Message)
		}
		if !strings.Contains(e.Message, "/shodan/host/8.8.8.8") {
			t.Errorf("%s: the message does not name the endpoint: %s", name, e.Message)
		}
	}
}

func TestACancelledContextIsATimeoutWithoutTheKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, err := newClient(srv.URL, 5*time.Second).Host(ctx, "8.8.8.8")
	e := clientErr(t, err)
	if e.Code != CodeTimeout {
		t.Errorf("code = %q", e.Code)
	}
	assertNoKey(t, "cancelled", e.Message)
}

// A redirect is never followed: the key is in the query string, and Go would
// carry it to wherever Location points.
func TestRedirectsAreRefused(t *testing.T) {
	var elsewhere atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer target.Close()
	for _, status := range []int{301, 302, 307, 308} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/steal?"+r.URL.RawQuery, status)
		}))
		_, err := newClient(srv.URL, time.Second).Host(context.Background(), "8.8.8.8")
		srv.Close()
		e := clientErr(t, err)
		if e.Code != CodeEndpoint || !strings.Contains(e.Message, "redirect") {
			t.Errorf("%d: code %q, message %q", status, e.Code, e.Message)
		}
		assertNoKey(t, "redirect", e.Message)
	}
	if elsewhere.Load() != 0 {
		t.Errorf("a redirect was followed %d time(s)", elsewhere.Load())
	}
}

func TestStatusMapping(t *testing.T) {
	for name, tc := range map[string]struct {
		status      int
		ctype, body string
		code        string
		apiError    string
	}{
		// Measured shapes (RFP §7 and its Phase 1 corrections).
		"401 text/plain": {401, "text/plain; charset=UTF-8", "401 Unauthorized\n\nThis server could not verify ...", CodeAuthFailed, ""},
		"400 empty":      {400, "application/json", `{"error": "Empty search query"}`, CodeBadRequest, "Empty search query"},
		"404 no info":    {404, "application/json", `{"error": "No information available for that IP."}`, CodeEndpoint, "No information available for that IP."},
		"404 invalid ip": {404, "application/json", `{"error": "Invalid IP"}`, CodeEndpoint, "Invalid IP"},
		"404 not api":    {404, "text/html", `<html>gone</html>`, CodeEndpoint, ""},
		"500 syntax":     {500, "application/json", `{"error": "The search request has timed out or your query was invalid."}`, CodeUpstream, "The search request has timed out or your query was invalid."},
		"500 fetch":      {500, "application/json", `{"error": "Unable to fetch information"}`, CodeUpstream, "Unable to fetch information"},
		"429":            {429, "text/plain", "slow down", CodeRateLimited, ""},
		"403 unmapped":   {403, "text/html", "forbidden", CodeUpstream, ""},
		"200 not json":   {200, "text/html", "<html>", CodeDecode, ""},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", tc.ctype)
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		_, err := newClient(srv.URL, time.Second).Count(context.Background(), "port:22", "")
		srv.Close()
		e := clientErr(t, err)
		if e.Code != tc.code || e.APIError != tc.apiError {
			t.Errorf("%s: code %q apiError %q, want %q %q", name, e.Code, e.APIError, tc.code, tc.apiError)
		}
		if tc.status != 200 && e.Status != tc.status {
			t.Errorf("%s: Status = %d", name, e.Status)
		}
		assertNoKey(t, name, e.Message)
	}
}

// Upstream's error text is third-party text: control characters are made
// inert, it is clipped, and if it ever echoed the key back, the key is gone.
func TestUpstreamErrorTextIsInertAndScrubbed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error": "bad \u001b[31mthing\u202e for ` + testKey + ` ` + strings.Repeat("x", 400) + `"}`))
	}))
	defer srv.Close()
	_, err := newClient(srv.URL, time.Second).Count(context.Background(), "port:22", "")
	e := clientErr(t, err)
	if strings.ContainsAny(e.Message, "\u001b\u202e") || strings.ContainsAny(e.APIError, "\u001b\u202e") {
		t.Errorf("control characters survived: %q", e.APIError)
	}
	if !strings.HasSuffix(e.APIError, "…") {
		t.Errorf("long upstream text was not clipped: %d bytes", len(e.APIError))
	}
	assertNoKey(t, "echoed key", e.Message, e.APIError)
	if !strings.Contains(e.APIError, "[redacted]") {
		t.Errorf("the echoed key was not replaced: %q", e.APIError)
	}
}

func TestAnOversizedBodyIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat(" ", 1<<20))
		_, _ = w.Write([]byte("["))
		for i := 0; i <= maxBody>>20; i++ {
			_, _ = w.Write(chunk)
		}
	}))
	defer srv.Close()
	_, err := newClient(srv.URL, 10*time.Second).Host(context.Background(), "8.8.8.8")
	if e := clientErr(t, err); e.Code != CodeUpstream || !strings.Contains(e.Message, "MiB") {
		t.Errorf("code %q message %q", e.Code, e.Message)
	}
}

// Requests are spaced at least the interval apart; the first goes at once.
func TestPacingSpacesRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	now := time.Unix(1_700_000_000, 0)
	var slept []time.Duration
	c := New(srv.URL, testKey, time.Second, 2*time.Second, "t").WithClock(
		func() time.Time { return now },
		func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil })
	for i := 0; i < 3; i++ {
		if _, err := c.APIInfo(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(slept) != 2 || slept[0] != 2*time.Second || slept[1] != 4*time.Second {
		t.Errorf("slept %v, want [2s 4s] for three requests at one instant", slept)
	}
	now = now.Add(10 * time.Second)
	slept = nil
	if _, err := c.APIInfo(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(slept) != 0 {
		t.Errorf("slept %v after the interval had passed", slept)
	}
}

// (L1) A key quoted where the message is clipped must not leave its head
// behind: the scrub runs before the clip.
func TestAKeyQuotedAtTheClipIsStillScrubbed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error": "` + strings.Repeat("x", 290) + `key=` + testKey + `"}`))
	}))
	defer srv.Close()
	_, err := newClient(srv.URL, time.Second).Count(context.Background(), "port:22", "")
	e := clientErr(t, err)
	assertNoKey(t, "clipped", e.Message, e.APIError)
}
