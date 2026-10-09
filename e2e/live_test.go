//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/shodan-lookup/internal/app"
	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/config"
	"github.com/nlink-jp/shodan-lookup/internal/engine"
	"github.com/nlink-jp/shodan-lookup/internal/shodan"
)

// Fixtures are public services chosen for stability. None of the assertions
// pins a count that moves; where a fixture's meaning can drift (an address
// that might become indexed, a history that might start working), the test
// checks the premise first and fails naming the fixture, rather than passing
// on a meaning it lost.
const (
	googleDNS  = "8.8.8.8"                // a few services, 53 on tcp and udp; its history answers "no information"
	cloudflare = "1.1.1.1"                // many services, TLS on several ports
	quad9      = "9.9.9.9"                // a history that reaches the 1,000-banner cap
	unindexed  = "2001:4860:ffff:ffff::5" // an unused address in Google's block; unobserved when measured
	log4shell  = "CVE-2021-44228"         // vuln: answered 3 for it on Membership
	googleV6   = "2001:4860:4860::8888"
)

// allowedSpend is what the run may spend. The default suite spends nothing;
// the e2e_credits build sets it to the one credit its search costs.
var allowedSpend = 0

// One engine and one client, so one pacer, for the whole run: the limit is
// per key.
var (
	cfg    *config.Config
	client *shodan.Client
	eng    *engine.Engine
	key    string
)

func TestMain(m *testing.M) {
	// The key is the operator's: read it from their configuration before
	// anything else is isolated. It is never printed.
	real, err := config.Load(os.Getenv("SHODAN_LOOKUP_E2E_CONFIG"), 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: cannot load the configuration:", err)
		os.Exit(1)
	}
	if !real.HasKey() {
		fmt.Fprintln(os.Stderr, "e2e: no Shodan API key is configured, so the suite did not run. That is a failure, not a skip: a release gate that skips is a gate that passes")
		os.Exit(1)
	}
	key = real.APIKey

	dir, err := os.MkdirTemp("", "shodan-lookup-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cfg = real
	cfg.CacheDir = filepath.Join(dir, "cache") // never the operator's cache
	// The operator's floor protects their own searches; the suite's free
	// search must not fail on it near the end of a month.
	cfg.CreditFloor = 0
	client = shodan.New(cfg.BaseURL, key, cfg.Timeout, cfg.MinInterval, app.UserAgent("e2e"))
	eng = engine.New(cfg, client, &cache.Store{Dir: cfg.CacheDir})

	before, err := remaining()
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: cannot read the remaining credits:", err)
		os.Exit(1)
	}
	code := m.Run()
	after, err := remaining()
	switch {
	case err != nil:
		fmt.Fprintln(os.Stderr, "e2e: cannot read the remaining credits after the run:", err)
		code = 1
	case before-after != allowedSpend:
		fmt.Fprintf(os.Stderr, "e2e: the run spent %d query credit(s) (%d → %d); it may spend exactly %d\n", before-after, before, after, allowedSpend)
		code = 1
	default:
		fmt.Fprintf(os.Stderr, "e2e: query credits %d → %d — spent exactly the %d allowed\n", before, after, allowedSpend)
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func remaining() (int, error) {
	q, err := eng.GetQuota(context.Background())
	if err != nil {
		return 0, err
	}
	return q.QueryCredits, nil
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	return c
}

func countIP(t *testing.T, ip string) int {
	t.Helper()
	c, err := eng.CountServices(ctx(t), "ip:"+ip, nil, true)
	if err != nil {
		t.Fatalf("count ip:%s: %v", ip, err)
	}
	return c.Total
}

// ---- the tool works ---------------------------------------------------------

func TestLiveHost(t *testing.T) {
	h, err := eng.LookupHost(ctx(t), googleDNS, true)
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	transports := map[string]bool{}
	sha1 := false
	for _, s := range h.Services {
		if s.Port == 53 {
			transports[s.Transport] = true
		}
		if s.SSL != nil && len(s.SSL.SHA1) == 40 {
			sha1 = true
		}
		if s.Timestamp != "" && !strings.HasSuffix(s.Timestamp, "Z") {
			t.Errorf("timestamp %q is not UTC", s.Timestamp)
		}
	}
	if !transports["tcp"] || !transports["udp"] || !sha1 || h.Provenance.Cached {
		t.Errorf("8.8.8.8: 53 transports %v, a TLS sha1 %v, cached %v", transports, sha1, h.Provenance.Cached)
	}
	again, err := eng.LookupHost(ctx(t), googleDNS, false)
	if err != nil || !again.Provenance.Cached || again.Provenance.DocID != h.Provenance.DocID {
		t.Errorf("the second ask should be the cached record, same doc_id: %v", err)
	}

	v6, err := eng.LookupHost(ctx(t), googleV6, false)
	if err != nil || len(v6.Ports) == 0 {
		t.Errorf("IPv6 host: %v", err)
	}
}

func TestLiveService(t *testing.T) {
	_, err := eng.GetService(ctx(t), engine.ServiceQuery{IP: googleDNS, Port: 53, Section: engine.SectionBanner}, false)
	if engine.Code(err) != engine.CodeInvalidArgument {
		t.Errorf("53 has tcp and udp; without transport: %v", err)
	}
	p, err := eng.GetService(ctx(t), engine.ServiceQuery{IP: googleDNS, Port: 53, Transport: "udp", Section: engine.SectionBanner}, false)
	if err != nil || !strings.Contains(p.Text, "Recursion") {
		t.Errorf("53/udp banner: %+v %v", p, err)
	}
	c, err := eng.GetService(ctx(t), engine.ServiceQuery{IP: cloudflare, Port: 443, Section: engine.SectionCert, Limit: engine.MaxTextLimit}, false)
	if err != nil || !strings.Contains(c.Text, "fingerprint") {
		t.Errorf("1.1.1.1 443 certificate: %v", err)
	}
	h, err := eng.GetService(ctx(t), engine.ServiceQuery{IP: cloudflare, Port: 443, Section: engine.SectionHeaders}, false)
	if err != nil || h.Total == 0 {
		t.Errorf("http_headers is empty on 1.1.1.1:443 — AGENTS.md says Shodan carries headers as an object: %+v %v", h, err)
	}
}

func TestLiveNotIndexed(t *testing.T) {
	if n := countIP(t, unindexed); n != 0 {
		t.Fatalf("the fixture %s has lost its meaning: Shodan now holds %d service(s) for it. Pick another unobserved public address", unindexed, n)
	}
	_, err := eng.LookupHost(ctx(t), unindexed, true)
	if engine.Code(err) != engine.CodeNotIndexed {
		t.Errorf("an unobserved address: %q (%v), want not_indexed", engine.Code(err), err)
	}
}

func TestLiveCountAndFacets(t *testing.T) {
	c, err := eng.CountServices(ctx(t), "port:3389 country:JP", []engine.FacetSpec{{Name: "org", N: 3}, {Name: "ip", N: 3}}, true)
	if err != nil {
		t.Fatalf("CountServices: %v", err)
	}
	if c.Total < 1000 || len(c.Facets) != 2 || len(c.Facets[0].Values) != 3 || len(c.Facets[1].Values) != 3 {
		t.Errorf("count: total %d facets %+v", c.Total, c.Facets)
	}
}

func TestLiveHistory(t *testing.T) {
	h, err := eng.GetHistory(ctx(t), engine.HistoryQuery{IP: quad9}, true)
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if h.Window.Banners != engine.HistoryCap || !h.Window.Capped {
		t.Errorf("9.9.9.9's history returned %d banners; AGENTS.md says Shodan caps history at %d — if the cap moved, update HistoryCap and the Gotcha",
			h.Window.Banners, engine.HistoryCap)
	}
}

func TestLiveQuotaAndParseQuery(t *testing.T) {
	q, err := eng.GetQuota(ctx(t))
	if err != nil || q.Plan == "" {
		t.Fatalf("quota: %+v %v", q, err)
	}
	if q.Plan != "dev" {
		t.Logf("the plan is %q, not the measured Membership \"dev\": the plan-restriction pins below may not hold", q.Plan)
	}
	r, err := eng.ParseQuery(ctx(t), "product:nginx country:JP")
	if err != nil || r.PredictedCost != 1 {
		t.Errorf("filtered prediction: %+v %v", r, err)
	}
	r, err = eng.ParseQuery(ctx(t), "nginx")
	if err != nil || r.PredictedCost != 0 {
		t.Errorf("free-text prediction: %+v %v", r, err)
	}
}

// A free search goes through every step of the credit guard and spends
// nothing: unfiltered, page 1 (measured 0). TestMain's before/after read
// proves it.
func TestLiveFreeSearchRunsTheGuard(t *testing.T) {
	// Prevent, do not only detect: Shodan's own reading must predict 0 before
	// anything that could cost is sent.
	r, err := eng.ParseQuery(ctx(t), "nginx")
	if err != nil || r.PredictedCost != 0 {
		t.Fatalf("Shodan no longer reads \"nginx\" as free (prediction %+v, %v); not searching", r, err)
	}
	s, err := eng.SearchServices(ctx(t), engine.SearchQuery{Query: "nginx"}, true)
	if err != nil {
		t.Fatalf("SearchServices: %v", err)
	}
	if s.Credits == nil || s.Credits.Predicted != 0 || s.Credits.Spent == nil || *s.Credits.Spent != 0 || len(s.Rows) == 0 {
		t.Errorf("free search: credits %+v rows %d", s.Credits, len(s.Rows))
	}
}

func TestLiveBinary(t *testing.T) {
	bin, err := filepath.Abs(filepath.Join("..", "dist", "shodan-lookup"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("no binary at %s — run `make e2e`, which builds it. The binary is what ships; skipping it would leave the release gate green without having looked", bin)
	}
	home := t.TempDir()
	env := append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "config"),
		"XDG_CACHE_HOME="+filepath.Join(home, "cache"), "SHODAN_LOOKUP_API_KEY="+key)

	cmd := exec.CommandContext(ctx(t), bin, "host", cloudflare, "--json")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("host --json: %v", err)
	}
	var h engine.Host
	if err := json.Unmarshal(out, &h); err != nil || len(h.Services) < 5 {
		t.Errorf("host --json: %d services (%v); --json must be complete", len(h.Services), err)
	}
	if bytes.Contains(out, []byte(key)) {
		t.Error("the key appears in the output")
	}

	mcp := exec.CommandContext(ctx(t), bin, "mcp")
	mcp.Env = env
	mcp.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"lookup_host","arguments":{"ip":"` + cloudflare + `"}}}` + "\n")
	stdout, err := mcp.Output()
	if err != nil {
		t.Fatalf("mcp: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(stdout), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("mcp answered %d frames, want 2", len(lines))
	}
	var frame struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(lines[1], &frame); err != nil || frame.Result.IsError || len(frame.Result.Content) != 1 {
		t.Fatalf("lookup_host frame: %v %.300s", err, lines[1])
	}
	// The record is about 316 KB upstream. This is the response budget, live.
	if n := len(frame.Result.Content[0].Text); n > 64*1024 {
		t.Errorf("the default lookup_host answer for %s is %d bytes", cloudflare, n)
	}
}

// ---- upstream still behaves as measured --------------------------------------

// Why a host 404 is cross-checked: Shodan answers "no information" for the
// history of a host it holds services for.
func TestLiveHistoryNoInformationTrap(t *testing.T) {
	if n := countIP(t, googleDNS); n == 0 {
		t.Fatalf("the premise is gone: a count finds no services for %s", googleDNS)
	}
	_, err := client.HostHistory(ctx(t), googleDNS)
	var se *shodan.Error
	if err == nil {
		t.Errorf("Shodan now returns 8.8.8.8's history. Update the Gotcha in AGENTS.md (the cross-check stays — other hosts may still fail this way)")
		return
	}
	if !asError(err, &se) || se.Status != 404 || se.APIError != "No information available for that IP." {
		t.Errorf("8.8.8.8 history: %v — AGENTS.md describes a 404 \"No information available\"", err)
	}
	_, err = eng.GetHistory(ctx(t), engine.HistoryQuery{IP: googleDNS}, true)
	if engine.Code(err) != shodan.CodeUpstream || !strings.Contains(err.Error(), "did not return its history") {
		t.Errorf("the tool must not call it not_indexed: %q %v", engine.Code(err), err)
	}
}

// Why the key is checked by get_quota and count, never by host lookups.
func TestLiveHostLookupsDoNotCheckTheKey(t *testing.T) {
	wrong := shodan.New(cfg.BaseURL, strings.Repeat("0", 32), cfg.Timeout, cfg.MinInterval, app.UserAgent("e2e"))
	if _, err := wrong.Host(ctx(t), googleDNS); err != nil {
		t.Logf("a host lookup with a wrong key now fails (%v). Good — update the Gotcha in AGENTS.md", err)
	}
	_, err := wrong.Count(ctx(t), "port:22", "")
	if shodan.Code(err) != shodan.CodeAuthFailed {
		t.Errorf("count with a wrong key: %q (%v), want auth_failed", shodan.Code(err), err)
	}
}

// Why filter and facet names are checked before sending.
func TestLiveUnknownNamesAreSilentNoOps(t *testing.T) {
	resp, err := client.Count(ctx(t), "nosuchfilter:x", "")
	if err != nil {
		t.Logf("an unknown filter is now an error (%v). Good — update the Gotcha; the local check stays", err)
	} else if total(t, resp) != 0 {
		t.Errorf("an unknown filter now matches something: %s", resp.Body)
	}
	resp, err = client.Count(ctx(t), "port:22", "nosuchfacet:3")
	switch {
	case err != nil:
		t.Logf("an unknown facet is now an error (%v). Good — update the Gotcha; the local check stays", err)
	case bytes.Contains(resp.Body, []byte(`"facets"`)):
		t.Errorf("an unknown facet now comes back: %s", resp.Body)
	}
}

// Why vuln and tag are refused: the restriction reads as a low count.
func TestLiveVulnFilterReadsLow(t *testing.T) {
	resp, err := client.Count(ctx(t), "vuln:"+log4shell, "")
	if err != nil {
		t.Logf("vuln: now answers %v. Update the Gotcha; the refusal stays while the plan lacks the filter", err)
		return
	}
	if n := total(t, resp); n > 1000 {
		t.Errorf("vuln:%s now counts %d — the plan may have changed (see get_quota); reconsider the refusal", log4shell, n)
	}
}

// Why a SHA-256 fingerprint is refused.
func TestLiveFingerprintIsSHA1(t *testing.T) {
	h, err := eng.LookupHost(ctx(t), cloudflare, false)
	if err != nil {
		t.Fatal(err)
	}
	var sha1, sha256 string
	for _, s := range h.Services {
		if s.SSL != nil && s.SSL.SHA1 != "" && s.SSL.SHA256 != "" {
			sha1, sha256 = s.SSL.SHA1, s.SSL.SHA256
			break
		}
	}
	if sha1 == "" {
		t.Fatal("the fixture has lost its meaning: no TLS certificate on 1.1.1.1")
	}
	r1, err1 := client.Count(ctx(t), "ssl.cert.fingerprint:"+sha1, "")
	r2, err2 := client.Count(ctx(t), "ssl.cert.fingerprint:"+sha256, "")
	if err1 != nil || err2 != nil {
		t.Fatalf("counts: %v %v", err1, err2)
	}
	if total(t, r1) == 0 {
		t.Errorf("the certificate's SHA-1 now matches nothing — the manual's pivot is broken")
	}
	if total(t, r2) != 0 {
		t.Logf("a SHA-256 now matches (%d). Update the Gotcha and consider allowing it", total(t, r2))
	}
}

func total(t *testing.T, r *shodan.Response) int {
	t.Helper()
	var c struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(r.Body, &c); err != nil {
		t.Fatalf("count body: %v", err)
	}
	return c.Total
}

func asError(err error, out **shodan.Error) bool { return errors.As(err, out) }
