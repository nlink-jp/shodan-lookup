package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nlink-jp/shodan-lookup/internal/engine"
)

// fakeEngine stands in for the shared core. Its host has as many services,
// banners and CVEs as a test asks for.
type fakeEngine struct {
	services   int
	bannerSize int
	banner     string
	vulns      int
	err        error
	gotService engine.ServiceQuery
	gotFacets  []engine.FacetSpec
	page       *engine.Page
	gotHistory engine.HistoryQuery
}

func (f *fakeEngine) LookupHost(_ context.Context, ip string, _ bool) (*engine.Host, error) {
	if f.err != nil {
		return nil, f.err
	}
	h := &engine.Host{IP: ip, Services: []engine.Service{}, Vulns: []engine.Vuln{}}
	for i := 0; i < f.services; i++ {
		b := f.banner
		if b == "" {
			b = strings.Repeat("b", f.bannerSize)
		}
		h.Services = append(h.Services, engine.Service{Port: 1000 + i, Transport: "tcp", Banner: b, BannerChars: len([]rune(b))})
		h.Ports = append(h.Ports, 1000+i)
	}
	for i := 0; i < f.vulns; i++ {
		h.Vulns = append(h.Vulns, engine.Vuln{ID: "CVE-2000-" + strings.Repeat("0", 3) + string(rune('0'+i%10))})
	}
	h.ServiceCount, h.VulnCount = len(h.Services), len(h.Vulns)
	return h, nil
}

func (f *fakeEngine) GetService(_ context.Context, q engine.ServiceQuery, _ bool) (*engine.Page, error) {
	f.gotService = q
	if f.page != nil {
		return f.page, nil
	}
	return &engine.Page{IP: q.IP, Port: q.Port, Section: q.Section}, nil
}

func (f *fakeEngine) CountServices(_ context.Context, q string, facets []engine.FacetSpec, _ bool) (*engine.Count, error) {
	f.gotFacets = facets
	return &engine.Count{Query: q, Unit: "services", Total: 3}, nil
}

func (f *fakeEngine) GetHistory(_ context.Context, q engine.HistoryQuery, _ bool) (*engine.History, error) {
	f.gotHistory = q
	h := &engine.History{IP: q.IP, Window: engine.HistoryWindow{Banners: 30, Cap: engine.HistoryCap}}
	p := engine.PortHistory{Port: 443, Transport: "tcp", Observations: 30}
	for i := 0; i < 30; i++ {
		p.Variants = append(p.Variants, engine.Variant{Title: fmt.Sprintf("title %02d", i), Observations: 1})
	}
	p.VariantCount = len(p.Variants)
	h.Ports = []engine.PortHistory{p}
	return h, nil
}

func (f *fakeEngine) GetQuota(context.Context) (*engine.Quota, error) {
	return &engine.Quota{Plan: "dev", PlanName: "Membership", QueryCredits: 100}, nil
}

func lookupServer(t *testing.T, eng *fakeEngine) *Server {
	t.Helper()
	s := testServer(t)
	s.Eng = eng
	s.Cfg.DefaultServices, s.Cfg.DefaultVulns, s.Cfg.BannerBytes = 5, 3, 64
	return s
}

func call(t *testing.T, s *Server, tool string, args string) (map[string]any, string, bool) {
	t.Helper()
	resps := serve(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+args+`}}`)
	text, result := toolResultText(t, resps[0])
	isErr := result["isError"] == true
	var m map[string]any
	_ = json.Unmarshal([]byte(text), &m)
	return m, text, isErr
}

func TestLookupHostAppliesTheBudgetAndCountsWhatItDropped(t *testing.T) {
	m, text, isErr := call(t, lookupServer(t, &fakeEngine{services: 8, bannerSize: 100, vulns: 7}), ToolLookupHost, `{"ip":"1.2.3.4"}`)
	if isErr {
		t.Fatalf("error: %s", text)
	}
	if n := len(m["services"].([]any)); n != 5 {
		t.Errorf("services listed = %d, want the default 5", n)
	}
	if n := len(m["vulns"].([]any)); n != 3 {
		t.Errorf("vulns listed = %d, want 3", n)
	}
	om, _ := m["omitted"].(map[string]any)
	if om["services"] != 3.0 || om["vulns"] != 4.0 || om["banners_shortened"] != 5.0 {
		t.Errorf("omitted = %v", om)
	}
	if m["service_count"] != 8.0 || m["vuln_count"] != 7.0 {
		t.Errorf("the totals do not say what exists: %v %v", m["service_count"], m["vuln_count"])
	}
	b := m["services"].([]any)[0].(map[string]any)["banner"].(string)
	if !strings.HasSuffix(b, "…") || len(b) > 64+len("…") {
		t.Errorf("banner not clipped to 64 bytes: %d", len(b))
	}
}

func TestNothingDroppedMeansNoOmittedField(t *testing.T) {
	m, _, _ := call(t, lookupServer(t, &fakeEngine{services: 2, bannerSize: 10, vulns: 1}), ToolLookupHost, `{"ip":"1.2.3.4"}`)
	if _, present := m["omitted"]; present {
		t.Errorf("omitted present although nothing was dropped: %v", m["omitted"])
	}
}

// A banner of control characters is six bytes per character on the wire; the
// cap is in those bytes.
func TestBannersAreCappedAfterEscaping(t *testing.T) {
	hostile := strings.Repeat("\u0001", 40)
	m, _, _ := call(t, lookupServer(t, &fakeEngine{services: 1, banner: hostile}), ToolLookupHost, `{"ip":"1.2.3.4"}`)
	b := m["services"].([]any)[0].(map[string]any)["banner"].(string)
	if got := len([]rune(strings.TrimSuffix(b, "…"))); got != 64/6 {
		t.Errorf("kept %d control characters, want %d (64 bytes escaped)", got, 64/6)
	}
}

func TestClipEscaped(t *testing.T) {
	for _, tc := range []struct {
		in   string
		max  int
		want string
		cut  bool
	}{
		{"short", 10, "short", false},
		{"abcdef", 3, "abc…", true},
		{"日本語テキスト", 7, "日本…", true}, // 3 bytes each, never split
		{`a"b"c`, 4, `a"b…`, true},  // a + \" + b is exactly 4 escaped bytes
		{`a"b"c`, 3, `a"…`, true},
		{"x<y", 3, "x…", true},
	} {
		got, cut := clipEscaped(tc.in, tc.max)
		if got != tc.want || cut != tc.cut {
			t.Errorf("clipEscaped(%q, %d) = %q %v, want %q %v", tc.in, tc.max, got, cut, tc.want, tc.cut)
		}
	}
}

func TestPortsFilterNamesWhatShodanDidNotObserve(t *testing.T) {
	m, _, _ := call(t, lookupServer(t, &fakeEngine{services: 4, bannerSize: 5}), ToolLookupHost, `{"ip":"1.2.3.4","ports":[1001,9999]}`)
	svcs := m["services"].([]any)
	if len(svcs) != 1 || svcs[0].(map[string]any)["port"] != 1001.0 {
		t.Errorf("services = %v", svcs)
	}
	if nob, _ := m["ports_not_observed"].([]any); len(nob) != 1 || nob[0] != 9999.0 {
		t.Errorf("ports_not_observed = %v", m["ports_not_observed"])
	}
	if !strings.Contains(strings.Join(toStrings(m["notes"]), " "), "not evidence that they are closed") {
		t.Errorf("notes: %v", m["notes"])
	}
}

func TestPortsOnlyCountsInsteadOfListing(t *testing.T) {
	m, _, _ := call(t, lookupServer(t, &fakeEngine{services: 4, bannerSize: 5, vulns: 2}), ToolLookupHost, `{"ip":"1.2.3.4","ports_only":true}`)
	if len(m["services"].([]any)) != 0 || len(m["ports"].([]any)) != 4 {
		t.Errorf("ports_only: services %v ports %v", m["services"], m["ports"])
	}
	if om := m["omitted"].(map[string]any); om["services"] != 4.0 || om["vulns"] != 2.0 {
		t.Errorf("omitted = %v", om)
	}
}

// Past the soft budget, services are dropped and counted instead of the whole
// answer being withheld.
func TestAHugeHostIsThinnedNotWithheld(t *testing.T) {
	s := lookupServer(t, &fakeEngine{services: 200, bannerSize: 2000})
	s.Cfg.DefaultServices, s.Cfg.BannerBytes = 200, 2000
	m, text, isErr := call(t, s, ToolLookupHost, `{"ip":"1.2.3.4"}`)
	if isErr {
		t.Fatalf("withheld: %s", text[:200])
	}
	if len(text) > maxResultBytes {
		t.Errorf("result is %d bytes", len(text))
	}
	kept := len(m["services"].([]any))
	if om := m["omitted"].(map[string]any); kept+int(om["services"].(float64)) != 200 {
		t.Errorf("kept %d + omitted %v != 200", kept, om["services"])
	}
}

func TestLookupHostRefusesBadArguments(t *testing.T) {
	s := lookupServer(t, &fakeEngine{services: 1})
	for _, args := range []string{`{}`, `{"ip":"1.2.3.4","ports":[0]}`, `{"ip":"1.2.3.4","ports":[70000]}`, `{"ip":"1.2.3.4","port":443}`} {
		_, text, isErr := call(t, s, ToolLookupHost, args)
		if !isErr || !strings.Contains(text, CodeInvalidArgument) {
			t.Errorf("%s: %s", args, text)
		}
	}
}

func TestEngineCodesPassThrough(t *testing.T) {
	s := lookupServer(t, &fakeEngine{err: &engine.Error{Code: engine.CodeNotIndexed, Message: "not in Shodan's index"}})
	_, text, isErr := call(t, s, ToolLookupHost, `{"ip":"1.2.3.4"}`)
	if !isErr || !strings.Contains(text, `"code":"not_indexed"`) {
		t.Errorf("not_indexed did not pass through: %s", text)
	}
}

func TestGetServiceLimits(t *testing.T) {
	eng := &fakeEngine{}
	s := lookupServer(t, eng)
	if _, text, isErr := call(t, s, ToolGetService, `{"ip":"1.2.3.4","port":443,"section":"vulns"}`); isErr {
		t.Fatal(text)
	}
	if eng.gotService.Limit != mcpDefaultList {
		t.Errorf("list default = %d, want %d", eng.gotService.Limit, mcpDefaultList)
	}
	if _, _, isErr := call(t, s, ToolGetService, `{"ip":"1.2.3.4","port":443,"section":"banner"}`); isErr || eng.gotService.Limit != 0 {
		t.Errorf("text default should be the engine's (0), got %d", eng.gotService.Limit)
	}
	for _, args := range []string{
		`{"ip":"1.2.3.4","port":443,"section":"vulns","limit":51}`,
		`{"ip":"1.2.3.4","port":443,"section":"banner","limit":16001}`,
		`{"ip":"1.2.3.4","port":443,"section":"banner","limit":0}`,
		`{"ip":"1.2.3.4","section":"banner"}`,
	} {
		if _, text, isErr := call(t, s, ToolGetService, args); !isErr || !strings.Contains(text, CodeInvalidArgument) {
			t.Errorf("%s: %s", args, text)
		}
	}
}

// What a section returns is whole: a PEM certificate past 1000 characters and
// a long CVE summary are not shortened by the backstop.
func TestSectionContentIsNotShortened(t *testing.T) {
	pem := strings.Repeat("M", 1800)
	summary := strings.Repeat("s", 2635)
	for name, page := range map[string]*engine.Page{
		"chain": {Section: engine.SectionChain, Items: []any{pem}},
		"vulns": {Section: engine.SectionVulns, Items: []any{engine.SectionVuln{ID: "CVE-2000-0001", Summary: summary}}},
		"text":  {Section: engine.SectionHTML, Text: strings.Repeat("h", 15000)},
	} {
		s := lookupServer(t, &fakeEngine{page: page})
		_, text, isErr := call(t, s, ToolGetService, `{"ip":"1.2.3.4","port":443,"section":"`+page.Section+`"}`)
		if isErr {
			t.Fatalf("%s: %s", name, text[:min(200, len(text))])
		}
		if strings.Contains(text, "…") || strings.Contains(text, "shortened") {
			t.Errorf("%s: section content was shortened", name)
		}
	}
}

func TestCountServicesFacetBounds(t *testing.T) {
	eng := &fakeEngine{}
	s := lookupServer(t, eng)
	if _, text, isErr := call(t, s, ToolCountServices, `{"query":"port:22","facets":["org:5","ip"]}`); isErr {
		t.Fatal(text)
	}
	if len(eng.gotFacets) != 2 || eng.gotFacets[0] != (engine.FacetSpec{Name: "org", N: 5}) || eng.gotFacets[1].N != engine.DefaultFacetValues {
		t.Errorf("facets = %+v", eng.gotFacets)
	}
	for _, args := range []string{`{"query":"port:22","facets":["ip:101"]}`, `{"query":""}`, `{"facets":["ip"]}`} {
		if _, text, isErr := call(t, s, ToolCountServices, args); !isErr || !strings.Contains(text, CodeInvalidArgument) {
			t.Errorf("%s: %s", args, text)
		}
	}
}

func TestGetQuota(t *testing.T) {
	m, text, isErr := call(t, lookupServer(t, &fakeEngine{}), ToolGetQuota, `{}`)
	if isErr || m["plan_name"] != "Membership" {
		t.Errorf("quota: %s", text)
	}
	if _, _, isErr := call(t, lookupServer(t, &fakeEngine{}), ToolGetQuota, `{"verbose":true}`); !isErr {
		t.Error("an undeclared argument was accepted")
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// Variants past the cap are dropped from the oldest end — the newest are what
// the port answers with now — and counted.
func TestGetHistoryCapsVariantsKeepingTheNewest(t *testing.T) {
	m, text, isErr := call(t, lookupServer(t, &fakeEngine{}), ToolGetHistory, `{"ip":"1.2.3.4"}`)
	if isErr {
		t.Fatal(text)
	}
	port := m["ports"].([]any)[0].(map[string]any)
	vs := port["variants"].([]any)
	if len(vs) != mcpMaxVariants || vs[len(vs)-1].(map[string]any)["title"] != "title 29" || port["variant_count"] != 30.0 {
		t.Errorf("variants: %d, last %v, count %v", len(vs), vs[len(vs)-1], port["variant_count"])
	}
	if om := m["omitted"].(map[string]any); om["variants"] != 10.0 {
		t.Errorf("omitted = %v", om)
	}
}

func TestGetHistoryArguments(t *testing.T) {
	eng := &fakeEngine{}
	s := lookupServer(t, eng)
	if _, text, isErr := call(t, s, ToolGetHistory, `{"ip":"1.2.3.4","port":443}`); isErr || eng.gotHistory.Limit != mcpDefaultList {
		t.Errorf("default observation limit %d (%s)", eng.gotHistory.Limit, text)
	}
	for _, args := range []string{`{}`, `{"ip":"1.2.3.4","limit":5}`, `{"ip":"1.2.3.4","port":443,"limit":51}`, `{"ip":"1.2.3.4","transport":"tcp"}`} {
		if _, text, isErr := call(t, s, ToolGetHistory, args); !isErr || !strings.Contains(text, CodeInvalidArgument) {
			t.Errorf("%s: %s", args, text)
		}
	}
}
