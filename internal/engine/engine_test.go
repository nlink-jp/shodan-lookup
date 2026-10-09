package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/config"
	"github.com/nlink-jp/shodan-lookup/internal/shodan"
)

// Fixtures are hand-written and synthetic: the shapes follow what was
// measured, the values are invented. Nothing captured from Shodan is
// committed (RFP §4), and the address is the conventional example 1.2.3.4.
const hostFixture = `{
  "ip_str": "1.2.3.4", "org": "Example Hosting", "isp": "Example ISP", "asn": "AS64500",
  "country_code": "JP", "city": "Tokyo", "hostnames": ["host.example.test"], "domains": ["example.test"],
  "os": null, "tags": ["cloud"], "last_update": "2026-10-09T05:00:00.123456",
  "ports": [443, 22, 53], "vulns": ["CVE-2000-0002", "CVE-2000-0001", "CVE-2000-0009"],
  "data": [
    {"port": 443, "transport": "tcp", "timestamp": "2026-10-09T05:00:00.123456",
     "product": "ExampleServer", "version": "1.0", "cpe23": ["cpe:2.3:a:example:server:1.0"],
     "data": "HTTP/1.1 200 OK\r\nServer: ExampleServer\r\n\r\n", "_shodan": {"module": "https"},
     "http": {"status": 200, "title": "Welcome", "server": "ExampleServer", "location": "/",
              "html": "<html>hello</html>", "headers": {"server": "ExampleServer", "x-list": ["a", "b"]},
              "favicon": {"hash": -123456, "data": "AAAA", "location": "https://1.2.3.4/favicon.ico"}},
     "ssl": {"versions": ["TLSv1.3"], "chain": ["-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n", "second"],
             "cert": {"subject": {"CN": "host.example.test"}, "issuer": {"CN": "Example CA", "O": ["Example", "Org"]},
                      "issued": "20250101000000Z", "expires": "20260101000000Z", "expired": false,
                      "serial": 123456789012345678901234567890, "fingerprint": {"sha1": "f00d", "sha256": "abcd"}}},
     "vulns": {"CVE-2000-0001": {"cvss": 5.0, "cvss_version": 3.1, "epss": 0.01, "verified": false, "summary": "first", "references": ["https://example.test/1"]},
               "CVE-2000-0002": {"cvss": 9.8, "cvss_version": 3.1, "epss": 0.5, "verified": false, "summary": "second", "references": []}}},
    {"port": 22, "transport": "tcp", "timestamp": "2026-10-08T05:00:00", "product": "ExampleSSH",
     "data": "SSH-2.0-ExampleSSH", "_shodan": {"module": "ssh"},
     "vulns": {"CVE-2000-0002": {"cvss": 9.8, "cvss_version": 3.1, "epss": 0.5, "verified": true, "summary": "second", "references": []}}},
    {"port": 53, "transport": "udp", "timestamp": "2026-10-09T04:00:00", "data": "dns udp", "_shodan": {"module": "dns-udp"}},
    {"port": 53, "transport": "tcp", "timestamp": "2026-10-09T04:00:00", "data": "dns tcp", "_shodan": {"module": "dns-tcp"}}
  ]
}`

var fixedNow = time.Date(2026, 10, 9, 7, 0, 0, 0, time.UTC)

type fakeUp struct {
	mu        sync.Mutex
	hosts     map[string]string // ip -> body
	histories map[string]string // ip -> history body
	filtersRaw string // when set, the filters list answers this body
	hostErr   map[string]error
	totals    map[string]int // count query -> total
	countErr  error
	countRaw  map[string]string // count query+"|"+facets -> body
	filters   []string
	facets    []string
	apiInfo   string
	calls     []string
}

func newFake() *fakeUp {
	return &fakeUp{
		hosts:   map[string]string{"1.2.3.4": hostFixture},
		hostErr: map[string]error{}, totals: map[string]int{}, countRaw: map[string]string{}, histories: map[string]string{},
		filters: []string{"port", "country", "org", "ip", "net", "http.title", "product", "vuln", "tag", "has_vuln", "ssl.cert.fingerprint"},
		facets:  []string{"port", "country", "org", "ip", "vuln", "vuln.verified"},
		apiInfo: `{"plan": "dev", "query_credits": 97, "scan_credits": 100, "monitored_ips": 0,
		           "usage_limits": {"query_credits": 100, "scan_credits": 100, "monitored_ips": 16}}`,
	}
}

func (f *fakeUp) record(c string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
}

func (f *fakeUp) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func resp(body, endpoint string) *shodan.Response {
	return &shodan.Response{Body: json.RawMessage(body), Endpoint: endpoint, FetchedAt: fixedNow}
}

func (f *fakeUp) Host(_ context.Context, ip string) (*shodan.Response, error) {
	f.record("host " + ip)
	if err := f.hostErr[ip]; err != nil {
		return nil, err
	}
	b, ok := f.hosts[ip]
	if !ok {
		return nil, &shodan.Error{Code: shodan.CodeEndpoint, Status: 404, APIError: noInformation, Message: "404"}
	}
	return resp(b, "/shodan/host/"+ip), nil
}

func (f *fakeUp) HostHistory(_ context.Context, ip string) (*shodan.Response, error) {
	f.record("history " + ip)
	b, ok := f.histories[ip]
	if !ok {
		return nil, &shodan.Error{Code: shodan.CodeEndpoint, Status: 404, APIError: noInformation, Message: "404"}
	}
	return resp(b, "/shodan/host/"+ip+"?history=true"), nil
}

func (f *fakeUp) Count(_ context.Context, query, facets string) (*shodan.Response, error) {
	f.record("count " + query + "|" + facets)
	if f.countErr != nil {
		return nil, f.countErr
	}
	if b, ok := f.countRaw[query+"|"+facets]; ok {
		return resp(b, "/shodan/host/count"), nil
	}
	return resp(`{"matches": [], "total": `+itoa(f.totals[query])+`}`, "/shodan/host/count"), nil
}

func (f *fakeUp) Filters(context.Context) (*shodan.Response, error) {
	f.record("filters")
	if f.filtersRaw != "" {
		return resp(f.filtersRaw, "/shodan/host/search/filters"), nil
	}
	b, _ := json.Marshal(f.filters)
	return resp(string(b), "/shodan/host/search/filters"), nil
}

func (f *fakeUp) Facets(context.Context) (*shodan.Response, error) {
	f.record("facets")
	b, _ := json.Marshal(f.facets)
	return resp(string(b), "/shodan/host/search/facets"), nil
}

func (f *fakeUp) APIInfo(context.Context) (*shodan.Response, error) {
	f.record("apiinfo")
	return resp(f.apiInfo, "/api-info"), nil
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func testEngine(t *testing.T, up *fakeUp) *Engine {
	t.Helper()
	cfg := &config.Config{APIKey: "k", HostTTL: config.DefaultHostTTL, CountTTL: config.DefaultCountTTL, SearchTTL: config.DefaultSearchTTL}
	return New(cfg, up, &cache.Store{Dir: t.TempDir()}).WithClock(func() time.Time { return fixedNow })
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if Code(err) != code {
		t.Fatalf("code = %q (%v), want %q", Code(err), err, code)
	}
}

func TestLookupHostProjects(t *testing.T) {
	h, err := testEngine(t, newFake()).LookupHost(context.Background(), "1.2.3.4", false)
	if err != nil {
		t.Fatal(err)
	}
	if h.IP != "1.2.3.4" || h.ASN != "AS64500" || h.OS != "" || h.LastUpdate != "2026-10-09T05:00:00Z" {
		t.Errorf("host attributes: %+v", h)
	}
	if len(h.Ports) != 3 || h.Ports[0] != 22 || h.Ports[1] != 53 || h.Ports[2] != 443 {
		t.Errorf("ports not sorted: %v", h.Ports)
	}
	// Services by port, then transport: 22, 53/tcp, 53/udp, 443.
	order := ""
	for _, s := range h.Services {
		order += itoa(s.Port) + s.Transport + " "
	}
	if order != "22tcp 53tcp 53udp 443tcp " {
		t.Errorf("service order = %q", order)
	}
	https := h.Services[3]
	if https.Timestamp != "2026-10-09T05:00:00Z" || https.AgeHours == nil || *https.AgeHours != 2.0 {
		t.Errorf("timestamp %q age %v", https.Timestamp, https.AgeHours)
	}
	if https.HTTP == nil || https.HTTP.Title != "Welcome" || https.HTTP.HTMLChars != len("<html>hello</html>") {
		t.Errorf("http: %+v", https.HTTP)
	}
	if https.FaviconHash == nil || *https.FaviconHash != -123456 {
		t.Errorf("favicon hash: %v", https.FaviconHash)
	}
	// Expired is computed now, not taken from the observation ("expired": false).
	if s := https.SSL; s == nil || s.Expired == nil || !*s.Expired || s.ExpiredAsOf != "2026-10-09T07:00:00Z" ||
		s.NotAfter != "2026-01-01T00:00:00Z" || s.SubjectCN != "host.example.test" || s.IssuerCN != "Example CA" ||
		s.SHA1 != "f00d" || s.SHA256 != "abcd" {
		t.Errorf("ssl: %+v", https.SSL)
	}
	// Vulns: union of services and the host list, highest CVSS first; verified
	// if any service verified it; a listed ID with no scored entry still counts.
	if h.VulnCount != 3 || h.Vulns[0].ID != "CVE-2000-0002" || !h.Vulns[0].Verified || len(h.Vulns[0].Ports) != 2 ||
		h.Vulns[1].ID != "CVE-2000-0001" || h.Vulns[2].ID != "CVE-2000-0009" || h.Vulns[2].CVSS != nil {
		t.Errorf("vulns: %+v", h.Vulns)
	}
	names := map[string]int{}
	for _, ix := range https.Sections {
		names[ix.Name] = ix.Size
	}
	if names[SectionHTML] != 18 || names[SectionHeaders] != 2 || names[SectionChain] != 2 || names[SectionVulns] != 2 {
		t.Errorf("section index: %+v", https.Sections)
	}
	if h.Provenance.Source != "shodan" || h.Provenance.Cached || h.Provenance.DocID == "" {
		t.Errorf("provenance: %+v", h.Provenance)
	}
}

func TestTheCacheServesAndRefreshFetches(t *testing.T) {
	up := newFake()
	e := testEngine(t, up)
	for i := 0; i < 2; i++ {
		if _, err := e.LookupHost(context.Background(), "1.2.3.4", false); err != nil {
			t.Fatal(err)
		}
	}
	if n := up.count("host"); n != 1 {
		t.Errorf("host fetched %d times for two lookups", n)
	}
	h, _ := e.LookupHost(context.Background(), "1.2.3.4", false)
	if !h.Provenance.Cached {
		t.Error("a cache hit is not reported as cached")
	}
	if _, err := e.LookupHost(context.Background(), "1.2.3.4", true); err != nil {
		t.Fatal(err)
	}
	if n := up.count("host"); n != 2 {
		t.Errorf("refresh did not fetch (host calls %d)", n)
	}
}

func TestAZeroTTLNeverCaches(t *testing.T) {
	up := newFake()
	e := testEngine(t, up)
	e.cfg.HostTTL = 0
	for i := 0; i < 2; i++ {
		if _, err := e.LookupHost(context.Background(), "1.2.3.4", false); err != nil {
			t.Fatal(err)
		}
	}
	if n := up.count("host"); n != 2 {
		t.Errorf("host fetched %d times with caching off", n)
	}
	if st := e.cache.Stat(); st.Entries != 0 {
		t.Errorf("%d entries written with a TTL of 0", st.Entries)
	}
}

// The 404 "No information" becomes not_indexed only when a count confirms
// zero; otherwise it is an upstream failure, never a negative answer.
func TestNoInformationIsConfirmedBeforeItIsAnAnswer(t *testing.T) {
	up := newFake()
	e := testEngine(t, up)

	_, err := e.LookupHost(context.Background(), "5.6.7.8", false)
	wantCode(t, err, CodeNotIndexed)
	if !strings.Contains(err.Error(), "not evidence that nothing is open") {
		t.Errorf("message: %v", err)
	}
	if up.count("count ip:5.6.7.8|") != 1 {
		t.Errorf("the 404 was not cross-checked: %v", up.calls)
	}
	// not_indexed is never cached: asking again asks again.
	_, _ = e.LookupHost(context.Background(), "5.6.7.8", false)
	if up.count("host 5.6.7.8") != 2 {
		t.Error("a not_indexed answer was cached")
	}

	up.totals["ip:5.6.7.8"] = 15
	_, err = e.LookupHost(context.Background(), "5.6.7.8", false)
	wantCode(t, err, shodan.CodeUpstream)
	if !strings.Contains(err.Error(), "15 service") || !strings.Contains(err.Error(), "not a negative answer") {
		t.Errorf("message: %v", err)
	}

	up.countErr = &shodan.Error{Code: shodan.CodeTimeout, Message: "t"}
	_, err = e.LookupHost(context.Background(), "5.6.7.8", false)
	wantCode(t, err, shodan.CodeUpstream)
	if !strings.Contains(err.Error(), "not evidence") {
		t.Errorf("a failed confirmation reads as an answer: %v", err)
	}
}

func TestOtherHost404s(t *testing.T) {
	up := newFake()
	up.hostErr["5.6.7.8"] = &shodan.Error{Code: shodan.CodeEndpoint, Status: 404, APIError: invalidIP, Message: "404"}
	up.hostErr["5.6.7.9"] = &shodan.Error{Code: shodan.CodeEndpoint, Status: 404, Message: "404 html"}
	e := testEngine(t, up)
	_, err := e.LookupHost(context.Background(), "5.6.7.8", false)
	wantCode(t, err, CodeInvalidArgument)
	_, err = e.LookupHost(context.Background(), "5.6.7.9", false)
	wantCode(t, err, shodan.CodeEndpoint)
	if up.count("count") != 0 {
		t.Error("a 404 other than \"no information\" was cross-checked")
	}
}

func TestTheGateAndTheKeyComeFirst(t *testing.T) {
	up := newFake()
	e := testEngine(t, up)
	_, err := e.LookupHost(context.Background(), "10.0.0.1", false)
	wantCode(t, err, CodeInvalidArgument)
	_, err = e.CountServices(context.Background(), "net:192.168.0.0/16", nil, false)
	wantCode(t, err, CodeInvalidArgument)
	if len(up.calls) != 0 {
		t.Errorf("an internal address reached upstream: %v", up.calls)
	}

	// A cached answer is not served without a key either.
	if _, err := e.LookupHost(context.Background(), "1.2.3.4", false); err != nil {
		t.Fatal(err)
	}
	e.cfg.APIKey = ""
	_, err = e.LookupHost(context.Background(), "1.2.3.4", false)
	wantCode(t, err, shodan.CodeMissingKey)
}

func TestGetServicePages(t *testing.T) {
	up := newFake()
	e := testEngine(t, up)
	ctx := context.Background()

	p, err := e.GetService(ctx, ServiceQuery{IP: "1.2.3.4", Port: 443, Section: SectionBanner, Limit: 10}, false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Text != "HTTP/1.1 2" || p.NextOffset == nil || *p.NextOffset != 10 || p.Unit != unitChars || p.Transport != "tcp" {
		t.Errorf("banner page: %+v", p)
	}
	// The first page came from a fetch, this lookup from the cache: one
	// record, one doc_id.
	h, _ := e.LookupHost(ctx, "1.2.3.4", false)
	if !h.Provenance.Cached || p.Provenance.DocID != h.Provenance.DocID {
		t.Errorf("the record's doc_id changed between a fetch and a cache hit (cached=%v)", h.Provenance.Cached)
	}

	last, _ := e.GetService(ctx, ServiceQuery{IP: "1.2.3.4", Port: 443, Section: SectionBanner, Offset: 40, Limit: 100}, false)
	if last.NextOffset != nil || last.Text != "\r\n" {
		t.Errorf("last page: %+v", last)
	}

	hdr, _ := e.GetService(ctx, ServiceQuery{IP: "1.2.3.4", Port: 443, Section: SectionHeaders}, false)
	if len(hdr.Items) != 2 || hdr.Items[0] != "server: ExampleServer" || hdr.Items[1] != "x-list: a, b" {
		t.Errorf("headers: %v", hdr.Items)
	}

	v, _ := e.GetService(ctx, ServiceQuery{IP: "1.2.3.4", Port: 443, Section: SectionVulns}, false)
	if len(v.Items) != 2 || v.Items[0].(SectionVuln).ID != "CVE-2000-0001" || v.Items[0].(SectionVuln).Summary != "first" {
		t.Errorf("vulns section: %+v", v.Items)
	}

	// The certificate is re-indented, never decoded: a serial too large for a
	// float64 comes back digit for digit.
	c, _ := e.GetService(ctx, ServiceQuery{IP: "1.2.3.4", Port: 443, Section: SectionCert, Limit: MaxTextLimit}, false)
	if !strings.Contains(c.Text, "123456789012345678901234567890") {
		t.Errorf("the serial was altered:\n%s", c.Text)
	}

	ssh, _ := e.GetService(ctx, ServiceQuery{IP: "1.2.3.4", Port: 22, Section: SectionHTML}, false)
	if ssh.Total != 0 || len(ssh.Notes) == 0 {
		t.Errorf("an absent section is not stated: %+v", ssh)
	}

	_, err = e.GetService(ctx, ServiceQuery{IP: "1.2.3.4", Port: 53, Section: SectionBanner}, false)
	wantCode(t, err, CodeInvalidArgument)
	if !strings.Contains(err.Error(), "tcp, udp") {
		t.Errorf("the ambiguity does not list the candidates: %v", err)
	}
	udp, err := e.GetService(ctx, ServiceQuery{IP: "1.2.3.4", Port: 53, Transport: "udp", Section: SectionBanner}, false)
	if err != nil || udp.Text != "dns udp" {
		t.Errorf("udp: %+v %v", udp, err)
	}

	_, err = e.GetService(ctx, ServiceQuery{IP: "1.2.3.4", Port: 8080, Section: SectionBanner}, false)
	wantCode(t, err, CodeNotObserved)
	if !strings.Contains(err.Error(), "not evidence that the port is closed") {
		t.Errorf("message: %v", err)
	}

	for _, q := range []ServiceQuery{
		{IP: "1.2.3.4", Port: 443, Section: "html"},
		{IP: "1.2.3.4", Port: 0, Section: SectionBanner},
		{IP: "1.2.3.4", Port: 443, Transport: "sctp", Section: SectionBanner},
		{IP: "1.2.3.4", Port: 443, Section: SectionBanner, Offset: -1},
		{IP: "1.2.3.4", Port: 443, Section: SectionBanner, Offset: 1000},
		{IP: "1.2.3.4", Port: 443, Section: SectionBanner, Limit: MaxTextLimit + 1},
		{IP: "1.2.3.4", Port: 443, Section: SectionVulns, Limit: MaxListLimit + 1},
	} {
		_, err := e.GetService(ctx, q, false)
		wantCode(t, err, CodeInvalidArgument)
	}
	if up.count("host") != 1 {
		t.Errorf("paging refetched the record: %d host calls", up.count("host"))
	}
}

func TestCountChecksNamesBeforeSending(t *testing.T) {
	up := newFake()
	e := testEngine(t, up)
	ctx := context.Background()

	for q, code := range map[string]string{
		"ssl.cert.fingerprint:" + strings.Repeat("ab", 32): CodeInvalidArgument, // a SHA-256 matches nothing (measured)
		"nosuchfilter:x":     CodeInvalidArgument,
		"Port:22":            CodeInvalidArgument,
		"vuln:CVE-2021-0001": CodePlanRestricted,
		"-tag:ics port:22":   CodePlanRestricted,
	} {
		_, err := e.CountServices(ctx, q, nil, false)
		wantCode(t, err, code)
	}
	_, err := e.CountServices(ctx, "port:22", []FacetSpec{{Name: "nosuchfacet", N: 3}}, false)
	wantCode(t, err, CodeInvalidArgument)
	_, err = e.CountServices(ctx, "port:22", []FacetSpec{{Name: "vuln", N: 3}}, false)
	wantCode(t, err, CodePlanRestricted)
	_, err = e.CountServices(ctx, "port:22", []FacetSpec{{Name: "org", N: 3}, {Name: "org", N: 5}}, false)
	wantCode(t, err, CodeInvalidArgument)
	if up.count("count") != 0 {
		t.Errorf("a refused query was sent: %v", up.calls)
	}

	// Free text and quoted colons are not filters.
	up.totals[`apache "Server: x"`] = 4
	c, err := e.CountServices(ctx, `apache "Server: x"`, nil, false)
	if err != nil || c.Total != 4 || c.Unit != "services" {
		t.Errorf("free-text count: %+v %v", c, err)
	}
	// A query whose names are all known is answered from the cached list.
	before := up.count("filters")
	if _, err := e.CountServices(ctx, "port:22 country:JP", nil, false); err != nil {
		t.Fatal(err)
	}
	if up.count("filters") != before {
		t.Errorf("the filter list was fetched again for known names")
	}
}

func TestCountReadsFacets(t *testing.T) {
	up := newFake()
	up.countRaw["port:22 country:JP|port:3,org:2"] = `{"matches": [], "total": 120,
	  "facets": {"port": [{"count": 100, "value": 22}], "org": [{"count": 60, "value": "Example Hosting"}, {"count": 5, "value": "Other"}]}}`
	e := testEngine(t, up)
	c, err := e.CountServices(context.Background(), "port:22 country:JP",
		[]FacetSpec{{Name: "port", N: 3}, {Name: "org", N: 2}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Total != 120 || len(c.Facets) != 2 || c.Facets[0].Values[0].Value != "22" || c.Facets[1].Values[1].Count != 5 {
		t.Errorf("facets: %+v", c.Facets)
	}
	joined := strings.Join(c.Notes, " ")
	if !strings.Contains(joined, "not hosts") || !strings.Contains(joined, "top values") {
		t.Errorf("notes: %v", c.Notes)
	}
}

func TestParseFacet(t *testing.T) {
	if f, err := ParseFacet("ip:100"); err != nil || f.Name != "ip" || f.N != 100 {
		t.Errorf("ip:100 → %+v %v", f, err)
	}
	if f, _ := ParseFacet("org"); f.N != DefaultFacetValues {
		t.Errorf("default N = %d", f.N)
	}
	for _, bad := range []string{"", ":3", "ip:0", "ip:1001", "ip:x"} {
		if _, err := ParseFacet(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestQuotaIsAlwaysLive(t *testing.T) {
	up := newFake()
	e := testEngine(t, up)
	for i := 0; i < 2; i++ {
		q, err := e.GetQuota(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if q.Plan != "dev" || q.PlanName != "Membership" || q.QueryCredits != 97 || q.Limits.QueryCredits != 100 {
			t.Errorf("quota: %+v", q)
		}
	}
	if up.count("apiinfo") != 2 {
		t.Error("the quota was cached")
	}
}

func TestCodeClassifiesEveryLayer(t *testing.T) {
	if Code(errors.New("x")) != "" {
		t.Error("an unclassified error got a code")
	}
	if Code(&shodan.Error{Code: shodan.CodeTimeout}) != shodan.CodeTimeout {
		t.Error("client codes do not pass through")
	}
}

// The fingerprint filter takes SHA-1; a SHA-1 passes the check.
func TestASHA1FingerprintIsSent(t *testing.T) {
	up := newFake()
	up.filters = append(up.filters, "ssl.cert.fingerprint")
	up.totals["ssl.cert.fingerprint:"+strings.Repeat("a1", 20)] = 7
	c, err := testEngine(t, up).CountServices(context.Background(), "ssl.cert.fingerprint:"+strings.Repeat("a1", 20), nil, false)
	if err != nil || c.Total != 7 {
		t.Errorf("sha1 pivot: %+v %v", c, err)
	}
}

// The independent verification of b30dde9 found these (M2, M3, M6, L4, L10).

// U+2028 and U+2029 are rewritten by encoding/json whatever SetEscapeHTML
// says; a fresh record and its cache hit must still hash the same.
func TestLineSeparatorsDoNotMoveTheDocID(t *testing.T) {
	up := newFake()
	up.hosts["1.2.3.4"] = strings.Replace(hostFixture, "SSH-2.0-ExampleSSH", "SSH-2.0-Example\u2028SSH\u2029", 1)
	e := testEngine(t, up)
	a, err := e.LookupHost(context.Background(), "1.2.3.4", false)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := e.LookupHost(context.Background(), "1.2.3.4", false)
	if !b.Provenance.Cached || a.Provenance.DocID != b.Provenance.DocID {
		t.Errorf("doc_id moved between a fetch and a cache hit: %s vs %s", a.Provenance.DocID, b.Provenance.DocID)
	}
	if !strings.Contains(b.Services[0].Banner, "Example\u2028SSH") {
		t.Errorf("the character itself was lost: %q", b.Services[0].Banner)
	}
}

// A body this tool cannot use is an error now, and is never cached.
func TestAnUnusableBodyIsNotCached(t *testing.T) {
	up := newFake()
	up.filtersRaw = `[]`
	e := testEngine(t, up)
	_, err := e.CountServices(context.Background(), "port:22", nil, false)
	wantCode(t, err, shodan.CodeDecode)
	up.filtersRaw = ""
	if _, err := e.CountServices(context.Background(), "port:22", nil, false); err != nil {
		t.Errorf("an unusable name list was cached: %v", err)
	}
	up.countRaw["port:23|"] = `{"matches": []}`
	_, err = e.CountServices(context.Background(), "port:23", nil, false)
	wantCode(t, err, shodan.CodeDecode)
	delete(up.countRaw, "port:23|")
	if _, err := e.CountServices(context.Background(), "port:23", nil, false); err != nil {
		t.Errorf("a count without a total was cached: %v", err)
	}
}

// A name Shodan added after the list was cached is fetched again once, not
// refused for the list's 24 hours; refresh reaches the lists too.
func TestANewNameRefetchesTheListOnce(t *testing.T) {
	up := newFake()
	e := testEngine(t, up)
	if _, err := e.CountServices(context.Background(), "port:22", nil, false); err != nil {
		t.Fatal(err)
	}
	up.filters = append(up.filters, "newfilter")
	if _, err := e.CountServices(context.Background(), "newfilter:x", nil, false); err != nil {
		t.Errorf("a name added upstream was refused from the cached list: %v", err)
	}
	if up.count("filters") != 2 {
		t.Errorf("filters fetched %d times, want 2", up.count("filters"))
	}
	if _, err := e.CountServices(context.Background(), "nosuch:x", nil, false); Code(err) != CodeInvalidArgument {
		t.Errorf("an unknown name after a fresh list: %v", err)
	}
	before := up.count("filters")
	_, _ = e.CountServices(context.Background(), "port:24", nil, true)
	if up.count("filters") != before+1 {
		t.Error("refresh did not reach the name list")
	}
}

func TestSHA256FingerprintsAreRefusedHoweverWritten(t *testing.T) {
	e := testEngine(t, newFake())
	hex := strings.Repeat("ab", 32)
	colons := strings.TrimSuffix(strings.Repeat("AB:", 32), ":")
	for _, q := range []string{
		"ssl.cert.fingerprint:" + hex,
		"ssl.cert.fingerprint:" + colons,
		`ssl.cert.fingerprint:" ` + hex + `"`,
		"ssl.cert.fingerprint:" + strings.Repeat("a1", 20) + "," + hex,
	} {
		_, err := e.CountServices(context.Background(), q, nil, false)
		wantCode(t, err, CodeInvalidArgument)
		if !strings.Contains(err.Error(), "SHA-1") {
			t.Errorf("%s: refused for another reason: %v", q, err)
		}
	}
}

// Host lookups do not check the key; when the cross-check's count refuses
// it, that is the answer — not "retry later".
func TestARefusedKeyDuringTheCrossCheckIsReportedAsSuch(t *testing.T) {
	up := newFake()
	up.countErr = &shodan.Error{Code: shodan.CodeAuthFailed, Status: 401, Message: "401"}
	_, err := testEngine(t, up).LookupHost(context.Background(), "5.6.7.8", false)
	wantCode(t, err, shodan.CodeAuthFailed)
}

func TestDerivedRestrictedNamesAreRefused(t *testing.T) {
	e := testEngine(t, newFake())
	_, err := e.CountServices(context.Background(), "has_vuln:true", nil, false)
	wantCode(t, err, CodePlanRestricted)
	_, err = e.CountServices(context.Background(), "port:22", []FacetSpec{{Name: "vuln.verified", N: 3}}, false)
	wantCode(t, err, CodePlanRestricted)
}
