package app

import (
	"bytes"
	"encoding/json"
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

type fakeShodan struct {
	srv   *httptest.Server
	hits  atomic.Int32
	paths []string
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
		case strings.HasPrefix(r.URL.Path, "/shodan/host/"):
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error": "No information available for that IP."}`))
		case r.URL.Path == "/api-info":
			_, _ = w.Write([]byte(`{"plan": "dev", "query_credits": 99, "scan_credits": 100, "monitored_ips": 0, "usage_limits": {"query_credits": 100, "scan_credits": 100, "monitored_ips": 16}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
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
