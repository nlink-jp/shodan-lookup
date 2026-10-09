package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nlink-jp/shodan-lookup/internal/engine"
	"github.com/nlink-jp/shodan-lookup/internal/termsafe"
)

// hostile is what an investigated host can put in its own banner: a terminal
// escape, a right-to-left override, a carriage return that would overwrite the
// line, and a newline that would forge a line of this tool's output.
const hostile = "evil\u001b[2J\u202ehidden\rover\nshodan-lookup: forged line"

// A synthetic host (shapes as measured, values invented; nothing captured).
func hostBody() string {
	b, _ := json.Marshal(map[string]any{
		"ip_str": "1.2.3.4", "org": "Example " + hostile, "asn": "AS64500", "country_code": "JP",
		"hostnames": []string{"h.example.test"}, "last_update": "2026-10-09T05:00:00.000000",
		"ports": []int{80, 53}, "vulns": []string{"CVE-2000-0001"},
		"data": []any{
			map[string]any{"port": 80, "transport": "tcp", "timestamp": "2026-10-09T05:00:00.000000",
				"product": "ExampleServer", "data": "HTTP/1.1 200 OK\r\nServer: " + hostile + "\r\n",
				"_shodan": map[string]any{"module": "http"},
				"http":    map[string]any{"status": 200, "title": hostile, "html": "<p>" + hostile + "</p>", "headers": map[string]any{"server": hostile}},
				"vulns": map[string]any{"CVE-2000-0001": map[string]any{"cvss": 7.5, "cvss_version": 3.0, "epss": 0.1, "verified": false,
					"summary": "summary " + hostile, "references": []string{"https://example.test/" + hostile}}}},
			map[string]any{"port": 53, "transport": "udp", "timestamp": "2026-10-09T04:00:00", "data": "dns", "_shodan": map[string]any{"module": "dns-udp"}},
		},
	})
	return string(b)
}

// A synthetic history: 443/tcp changes its title (hostile) and certificate.
func historyBody() string {
	var data []any
	for i, v := range []struct{ ts, title, sha1 string }{
		{"2026-10-07T01:00:00.000000", "Old", "aaaa"},
		{"2026-10-08T01:00:00.000000", hostile, "bbbb"},
		{"2026-10-09T01:00:00.000000", hostile, "bbbb"},
	} {
		data = append(data, map[string]any{"port": 443, "transport": "tcp", "timestamp": v.ts, "product": "ExampleServer",
			"data": "HTTP/1.1 200 OK\r\nX: " + hostile, "_shodan": map[string]any{"module": "https"}, "http": map[string]any{"title": v.title},
			"ssl": map[string]any{"cert": map[string]any{"fingerprint": map[string]any{"sha1": v.sha1}}}, "seq": i})
	}
	b, _ := json.Marshal(map[string]any{"ip_str": "1.2.3.4", "ports": []int{443}, "data": data})
	return string(b)
}

type fakeShodan struct {
	srv     *httptest.Server
	hits    atomic.Int32
	paths   []string
	credits atomic.Int32
}

func newFakeShodan(t *testing.T) *fakeShodan {
	t.Helper()
	f := &fakeShodan{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.paths = append(f.paths, r.URL.Path)
		if r.URL.Query().Get("key") != "test-key" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte("401 Unauthorized"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/shodan/host/1.2.3.4" && r.URL.Query().Get("history") == "true":
			_, _ = w.Write([]byte(historyBody()))
		case r.URL.Path == "/shodan/host/1.2.3.4":
			_, _ = w.Write([]byte(hostBody()))
		case r.URL.Path == "/shodan/host/count":
			if r.URL.Query().Get("facets") != "" {
				b, _ := json.Marshal(map[string]any{"matches": []any{}, "total": 120,
					"facets": map[string]any{"org": []any{map[string]any{"count": 60, "value": "Example " + hostile}}}})
				_, _ = w.Write(b)
				return
			}
			_, _ = w.Write([]byte(`{"matches": [], "total": 0}`))
		case r.URL.Path == "/shodan/host/search/filters":
			_, _ = w.Write([]byte(`["port", "country", "org", "ip", "net", "vuln", "tag"]`))
		case r.URL.Path == "/shodan/host/search/facets":
			_, _ = w.Write([]byte(`["port", "country", "org", "ip", "vuln"]`))
		case strings.HasPrefix(r.URL.Path, "/shodan/host/") && !strings.HasPrefix(r.URL.Path, "/shodan/host/search"):
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error": "No information available for that IP."}`))
		case r.URL.Path == "/api-info":
			_, _ = fmt.Fprintf(w, `{"plan": "dev", "query_credits": %d, "scan_credits": 100, "monitored_ips": 0, "usage_limits": {"query_credits": 100, "scan_credits": 100, "monitored_ips": 16}}`, f.credits.Load())
		case r.URL.Path == "/shodan/host/search/tokens":
			var filters []string
			for _, term := range strings.Fields(r.URL.Query().Get("query")) {
				if name, _, ok := strings.Cut(term, ":"); ok {
					filters = append(filters, name)
				}
			}
			b, _ := json.Marshal(map[string]any{"filters": append([]string{}, filters...), "errors": []string{}, "string": "", "attributes": map[string]any{}})
			_, _ = w.Write(b)
		case r.URL.Path == "/shodan/host/search":
			if strings.Contains(r.URL.Query().Get("query"), ":") || r.URL.Query().Get("page") != "1" {
				f.credits.Add(-1)
			}
			b, _ := json.Marshal(map[string]any{"total": 1, "matches": []any{map[string]any{
				"ip_str": "1.2.3.4", "port": 80, "transport": "tcp", "org": "Example", "product": "ExampleServer",
				"timestamp": "2026-10-09T05:00:00.000000", "_shodan": map[string]any{"module": "http"},
				"http": map[string]any{"title": hostile}, "data": "HTTP/1.1 200 OK\r\n" + hostile}}})
			_, _ = w.Write(b)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	f.credits.Store(99)
	return f
}

// online points the CLI at the fake upstream with a key, and paces nothing.
func online(t *testing.T) *fakeShodan {
	t.Helper()
	isolate(t)
	f := newFakeShodan(t)
	t.Setenv("SHODAN_LOOKUP_BASE_URL", f.srv.URL)
	t.Setenv("SHODAN_LOOKUP_API_KEY", "test-key")
	t.Setenv("SHODAN_LOOKUP_MIN_INTERVAL_MS", "1")
	return f
}

func runCLI(args ...string) (string, string, int) {
	var stdout, stderr bytes.Buffer
	code := run(args, "test", strings.NewReader(""), &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

// assertInert fails when output holds anything a terminal would obey other
// than the newlines of this tool's own layout.
func assertInert(t *testing.T, where, out string) {
	t.Helper()
	for _, r := range out {
		if r != '\n' && termsafe.Obeyed(r) {
			t.Errorf("%s: a raw U+%04X reached the terminal", where, r)
			return
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "shodan-lookup: forged line") {
			t.Errorf("%s: a newline in upstream text forged a line of output", where)
		}
	}
}

func TestHostPrintsAnInertProjection(t *testing.T) {
	online(t)
	out, errOut, code := runCLI("host", "1.2.3.4")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"1.2.3.4", "AS64500", "80/tcp", "53/udp", "CVE-2000-0001", "inferred", "source: Shodan /shodan/host/1.2.3.4"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	assertInert(t, "host text", out)
}

func TestHostJSONIsCompleteAndInert(t *testing.T) {
	online(t)
	out, _, code := runCLI("host", "1.2.3.4", "--json")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var h engine.Host
	if err := json.Unmarshal([]byte(out), &h); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	// Complete: the banner is whole, and the document still says what came.
	// Services are sorted by port: 53/udp, then 80/tcp.
	if len(h.Services) != 2 || h.Services[1].Port != 80 || !strings.Contains(h.Services[1].Banner, "forged line") {
		t.Errorf("--json is not complete: %+v", h.Services)
	}
	assertInert(t, "host --json", out)

	raw, _, code := runCLI("host", "1.2.3.4", "--raw")
	if code != exitOK || !json.Valid([]byte(raw)) || !strings.Contains(raw, `"ip_str": "1.2.3.4"`) {
		t.Errorf("--raw: exit %d, %.200s", code, raw)
	}
	assertInert(t, "host --raw", raw)
}

func TestHostNotIndexedIsAnAnswer(t *testing.T) {
	f := online(t)
	out, _, code := runCLI("host", "5.6.7.8")
	if code != exitOK || !strings.Contains(out, "not in Shodan's index") {
		t.Errorf("exit %d, output %q", code, out)
	}
	if f.paths[len(f.paths)-1] != "/shodan/host/count" {
		t.Errorf("the 404 was not cross-checked: %v", f.paths)
	}
}

func TestInternalAddressesAreNeverSent(t *testing.T) {
	f := online(t)
	for _, args := range [][]string{{"host", "10.0.0.1"}, {"host", "::ffff:192.168.1.1"}, {"count", "net:10.0.0.0/8"}, {"service", "172.16.0.1", "22", "--section", "banner"}} {
		_, errOut, code := runCLI(args...)
		if code != exitError || !strings.Contains(errOut, "invalid_argument") {
			t.Errorf("%v: exit %d, %s", args, code, errOut)
		}
	}
	if f.hits.Load() != 0 {
		t.Errorf("%d request(s) reached upstream", f.hits.Load())
	}
}

func TestAMissingKeyIsAConfigurationError(t *testing.T) {
	f := online(t)
	t.Setenv("SHODAN_LOOKUP_API_KEY", "")
	_, errOut, code := runCLI("host", "1.2.3.4")
	if code != exitError || !strings.Contains(errOut, "missing_api_key") || f.hits.Load() != 0 {
		t.Errorf("exit %d, hits %d, %s", code, f.hits.Load(), errOut)
	}
	t.Setenv("SHODAN_LOOKUP_API_KEY", "wrong-key")
	_, errOut, code = runCLI("quota")
	if code != exitError || !strings.Contains(errOut, "auth_failed") || strings.Contains(errOut, "wrong-key") {
		t.Errorf("a refused key: exit %d, %s", code, errOut)
	}
}

func TestServiceSections(t *testing.T) {
	online(t)
	out, errOut, code := runCLI("service", "1.2.3.4", "80", "--section", "banner")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "    | HTTP/1.1 200 OK") {
		t.Errorf("banner lines are not behind the gutter:\n%s", out)
	}
	assertInert(t, "service banner", out)

	for _, sec := range []string{"http_html", "http_headers", "vulns"} {
		out, errOut, code := runCLI("service", "1.2.3.4", "80", "--section", sec)
		if code != exitOK {
			t.Errorf("%s: exit %d %s", sec, code, errOut)
		}
		assertInert(t, "service "+sec, out)
	}
	if out, _, code := runCLI("service", "1.2.3.4", "8080", "--section", "banner"); code != exitOK || !strings.Contains(out, "not evidence that the port is closed") {
		t.Errorf("not_observed: exit %d %s", code, out)
	}
	if _, errOut, code := runCLI("service", "1.2.3.4", "80"); code != exitError || !strings.Contains(errOut, "--section") {
		t.Errorf("missing section: exit %d %s", code, errOut)
	}
	if _, errOut, code := runCLI("service", "1.2.3.4", "80", "--section", "banner", "--limit", "0"); code != exitError {
		t.Errorf("--limit 0: exit %d %s", code, errOut)
	}
}

func TestCount(t *testing.T) {
	online(t)
	out, errOut, code := runCLI("count", "port:22", "country:JP", "--facet", "org:5")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "port:22 country:JP") || !strings.Contains(out, "120 matching services") || !strings.Contains(out, "org (top 5)") {
		t.Errorf("output:\n%s", out)
	}
	assertInert(t, "count", out)

	for args, want := range map[string]string{
		"nosuchfilter:x": "invalid_argument",
		"vuln:CVE-1":     "plan_restricted",
	} {
		_, errOut, code := runCLI("count", args)
		if code != exitError || !strings.Contains(errOut, want) {
			t.Errorf("%s: exit %d %s", args, code, errOut)
		}
	}
	if _, errOut, code := runCLI("count", "port:22", "--facet", "ip:0"); code != exitError {
		t.Errorf("--facet ip:0: exit %d %s", code, errOut)
	}
}

func TestQuota(t *testing.T) {
	online(t)
	out, errOut, code := runCLI("quota")
	if code != exitOK || !strings.Contains(out, "dev (Membership)") || !strings.Contains(out, "99 of 100") {
		t.Errorf("exit %d, %s %s", code, out, errOut)
	}
	if _, _, code := runCLI("quota", "extra"); code != exitError {
		t.Error("quota accepted an argument")
	}
}

// Several IPs with --json are a stream of documents, errors included.
func TestHostJSONStream(t *testing.T) {
	online(t)
	out, _, code := runCLI("host", "1.2.3.4", "5.6.7.8", "--json")
	if code != exitOK {
		t.Errorf("exit %d", code)
	}
	dec := json.NewDecoder(strings.NewReader(out))
	n := 0
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		n++
		if n == 2 && m["error"].(map[string]any)["code"] != "not_indexed" {
			t.Errorf("second document: %v", m)
		}
	}
	if n != 2 {
		t.Errorf("%d documents, want 2", n)
	}
}

// Every string a renderer can print, filled with hostile text: the renderers
// must print nothing a terminal obeys, whatever field a later change adds.
func TestEveryHostFieldIsInertWhenPrinted(t *testing.T) {
	h := &engine.Host{}
	fillStrings(reflect.ValueOf(h).Elem())
	var out bytes.Buffer
	printHost(&out, forText(h), nil, false)
	assertInert(t, "printHost", out.String())

	c := &engine.Count{}
	fillStrings(reflect.ValueOf(c).Elem())
	out.Reset()
	forText(c)
	printNotes(&out, c.Notes)
	printProvenance(&out, c.Provenance)
	assertInert(t, "count renderers", out.String())
}

// fillStrings sets every reachable string to hostile text and gives every
// slice one element, so that a renderer meets each field.
func fillStrings(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() && v.CanSet() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		if !v.IsNil() {
			fillStrings(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				fillStrings(v.Field(i))
			}
		}
	case reflect.Slice:
		if v.CanSet() && v.Len() == 0 && v.Type().Elem().Kind() != reflect.Interface {
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		}
		for i := 0; i < v.Len(); i++ {
			fillStrings(v.Index(i))
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(hostile)
		}
	}
}

// A CRLF banner reads as lines; a lone CR — which would return the cursor and
// overwrite the line — is still shown, not obeyed.
func TestCRLFIsALineEndAndALoneCRIsShown(t *testing.T) {
	if got := visible("a\r\nb", true); got != "a\nb" {
		t.Errorf("multiline CRLF = %q", got)
	}
	if got := visible("a\rb", true); got != `a\x0db` {
		t.Errorf("multiline lone CR = %q", got)
	}
	if got := visible("a\r\nb", false); got != `a\x0d\x0ab` {
		t.Errorf("single-line CRLF = %q", got)
	}
	online(t)
	out, _, _ := runCLI("host", "1.2.3.4")
	if !strings.Contains(out, "banner: HTTP/1.1 200 OK  (") {
		t.Errorf("the banner's first line carries a CR or is missing:\n%s", out)
	}
}

func TestFirstLineSkipsBlankLines(t *testing.T) {
	if got := firstLine("\n\n  Recursion: enabled\nmore"); got != "Recursion: enabled" {
		t.Errorf("firstLine = %q", got)
	}
	if firstLine("\n \n") != "" {
		t.Error("a blank banner produced a line")
	}
}

// A gate refusal names the input once.
func TestARefusalNamesTheInputOnce(t *testing.T) {
	online(t)
	_, errOut, _ := runCLI("host", "10.0.0.1")
	if strings.Count(errOut, "10.0.0.1") != 1 {
		t.Errorf("the address is repeated: %s", errOut)
	}
}

func TestHistory(t *testing.T) {
	online(t)
	out, errOut, code := runCLI("history", "1.2.3.4")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"history 2026-10-07T01:00:00Z .. 2026-10-09T01:00:00Z  (3 banners)", "443/tcp", "2 variants", "cert aaaa", "cert bbbb", "not documented"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	assertInert(t, "history", out)

	out, errOut, code = runCLI("history", "1.2.3.4", "--port", "443", "--limit", "2")
	if code != exitOK || !strings.Contains(out, "observations, newest first (3, from 0)") || !strings.Contains(out, "more: --offset 2") {
		t.Errorf("observations: exit %d %s\n%s", code, errOut, out)
	}
	assertInert(t, "history --port", out)

	js, _, code := runCLI("history", "1.2.3.4", "--json")
	var h engine.History
	if code != exitOK || json.Unmarshal([]byte(js), &h) != nil || h.Window.Banners != 3 {
		t.Errorf("--json: exit %d %.200s", code, js)
	}
	assertInert(t, "history --json", js)
	raw, _, code := runCLI("history", "1.2.3.4", "--raw")
	if code != exitOK || !strings.Contains(raw, `"seq": 2`) {
		t.Errorf("--raw: exit %d %.200s", code, raw)
	}
	assertInert(t, "history --raw", raw)

	if out, _, code := runCLI("history", "5.6.7.8"); code != exitOK || !strings.Contains(out, "not in Shodan's index") {
		t.Errorf("unindexed: exit %d %s", code, out)
	}
	for _, args := range [][]string{{"history"}, {"history", "1.2.3.4", "--limit", "5"}, {"history", "1.2.3.4", "--port", "443", "--raw"}, {"history", "1.2.3.4", "--port", "0"}} {
		if _, _, code := runCLI(args...); code != exitError {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestEveryHistoryFieldIsInertWhenPrinted(t *testing.T) {
	h := &engine.History{}
	fillStrings(reflect.ValueOf(h).Elem())
	var out bytes.Buffer
	printHistory(&out, forText(h))
	assertInert(t, "printHistory", out.String())
}

// (L6) A certificate chain prints as lines behind the gutter, not as one line
// of \x0a escapes.
func TestChainItemsKeepTheirLines(t *testing.T) {
	online(t)
	out, errOut, code := runCLI("service", "1.2.3.4", "80", "--section", "http_headers")
	if code != exitOK {
		t.Fatalf("exit %d %s", code, errOut)
	}
	assertInert(t, "headers", out)
	if strings.Contains(out, `\x0a`) {
		t.Errorf("a newline was printed as an escape:\n%s", out)
	}
	if _, errOut, code := runCLI("host", "1.2.3.4", "--port", "80", "--ports-only"); code != exitError || !strings.Contains(errOut, "do not combine") {
		t.Errorf("--port with --ports-only: exit %d %s", code, errOut)
	}
}

func TestTokensPredicts(t *testing.T) {
	f := online(t)
	out, errOut, code := runCLI("tokens", "port:80", "apache")
	if code != exitOK || !strings.Contains(out, "filters:    port") || !strings.Contains(out, "spend 1 credit(s) for page 1") {
		t.Errorf("exit %d %s\n%s", code, errOut, out)
	}
	if f.credits.Load() != 99 {
		t.Error("tokens spent")
	}
}

func TestSearchSpendsReportsAndCaches(t *testing.T) {
	f := online(t)
	out, errOut, code := runCLI("search", "port:80")
	if code != exitOK {
		t.Fatalf("exit %d %s", code, errOut)
	}
	if !strings.Contains(errOut, "spent 1 query credit(s) (predicted 1): 99 → 98, floor 20") {
		t.Errorf("the spend is not reported on stderr: %q", errOut)
	}
	if !strings.Contains(out, "1 matching services") || !strings.Contains(out, "1.2.3.4") {
		t.Errorf("output:\n%s", out)
	}
	assertInert(t, "search", out+errOut)

	_, errOut, code = runCLI("search", "port:80")
	if code != exitOK || !strings.Contains(errOut, "no query credit was spent") || f.credits.Load() != 98 {
		t.Errorf("a cached page: exit %d, %q, credits %d", code, errOut, f.credits.Load())
	}

	raw, _, code := runCLI("search", "port:80", "--raw")
	if code != exitOK || !strings.Contains(raw, `"matches"`) {
		t.Errorf("--raw: exit %d %.200s", code, raw)
	}
	assertInert(t, "search --raw", raw)

	js, _, code := runCLI("search", "port:80", "--json")
	var s engine.Search
	if code != exitOK || json.Unmarshal([]byte(js), &s) != nil || len(s.Rows) != 1 {
		t.Errorf("--json: exit %d %.200s", code, js)
	}
}

func TestSearchBelowTheFloorSendsNothing(t *testing.T) {
	f := online(t)
	t.Setenv("SHODAN_LOOKUP_CREDIT_FLOOR", "99")
	_, errOut, code := runCLI("search", "apache")
	if code != exitError || !strings.Contains(errOut, "credit_floor") || f.credits.Load() != 99 {
		t.Errorf("exit %d, %s, credits %d", code, errOut, f.credits.Load())
	}
	for _, p := range f.paths {
		if p == "/shodan/host/search" {
			t.Error("a search was sent below the floor")
		}
	}
	if _, errOut, code := runCLI("search", "port:80", "--page", "11"); code != exitError {
		t.Errorf("--page 11: exit %d %s", code, errOut)
	}
}
