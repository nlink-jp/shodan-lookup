package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nlink-jp/shodan-lookup/internal/shodan"
)

type looseInner struct {
	N    *int     `json:"n"`
	Tags []string `json:"tags"`
}

type looseEmbedded struct {
	Port int `json:"port"`
}

type looseItem struct {
	ID   int   `json:"id" loose:"required"`
	Name *text `json:"name"`
}

type looseDoc struct {
	looseEmbedded
	Name   string                  `json:"name"`
	Ports  []int                   `json:"ports"`
	Inner  *looseInner             `json:"inner"`
	Byname map[string]looseInner   `json:"byname"`
	Items  []looseItem             `json:"items"`
	Raw    json.RawMessage         `json:"raw"`
	T      *text                   `json:"t"`
	Module struct{ Module string } `json:"_m"`
	Gone   string                  `json:"-"`
	hidden string
}

func TestDecodeLooseReadsWhatItCanAndCountsTheRest(t *testing.T) {
	var d looseDoc
	sk, err := decodeLoose([]byte(`{
	  "port": "443", "name": "x", "ports": [22, "80", 443, null],
	  "inner": {"n": "7", "tags": ["a", 1, "b"]},
	  "byname": {"k1": {"n": 1}, "k2": "secret-third-party-text", "k3": {"n": true}},
	  "items": [{"id": 1}, {"id": "x", "name": "y"}, {"id": 3, "name": {}}],
	  "raw": {"anything": [1, "2"]}, "t": 2497, "_m": {"MODULE": "ssh"}, "-": "no", "hidden": "no"}`), &d)
	if err != nil {
		t.Fatal(err)
	}
	if d.Port != 0 || d.Name != "x" || d.Module.Module != "ssh" || str(d.T) != "2497" || string(d.Raw) != `{"anything": [1, "2"]}` {
		t.Errorf("fields: %+v", d)
	}
	// A null element reads as the zero value, as encoding/json reads it.
	if len(d.Ports) != 3 || d.Ports[0] != 22 || d.Ports[1] != 443 || d.Ports[2] != 0 {
		t.Errorf("ports: %v", d.Ports)
	}
	if d.Inner == nil || d.Inner.N != nil || strings.Join(d.Inner.Tags, ",") != "a,b" {
		t.Errorf("inner: %+v", d.Inner)
	}
	// A map entry is kept by its key whatever its value; only the value's
	// unreadable parts are absent.
	if len(d.Byname) != 3 || d.Byname["k1"].N == nil || *d.Byname["k1"].N != 1 || d.Byname["k2"].N != nil || d.Byname["k3"].N != nil {
		t.Errorf("byname: %+v", d.Byname)
	}
	// An element whose required field cannot be read is left out whole —
	// never kept with a zero id.
	if len(d.Items) != 2 || d.Items[0].ID != 1 || d.Items[1].ID != 3 || d.Items[1].Name != nil {
		t.Errorf("items: %+v", d.Items)
	}
	if d.Gone != "" || d.hidden != "" {
		t.Errorf("an ignored field was set: %+v", d)
	}
	wantValues := map[string]int{"port": 1, "ports[]": 1, "inner.n": 1, "inner.tags[]": 1, "byname{}": 1, "byname{}.n": 1, "items[].name": 1}
	if len(sk.values) != len(wantValues) || len(sk.entries) != 1 || sk.entries["items[].id"] != 1 {
		t.Errorf("skipped = %v / %v, want %v / items[].id", sk.values, sk.entries, wantValues)
	}
	for p, n := range wantValues {
		if sk.values[p] != n {
			t.Errorf("values[%q] = %d, want %d (all: %v)", p, sk.values[p], n, sk.values)
		}
	}
	if sk.dropped("items[]") != 1 || sk.dropped("ports[]") != 0 {
		t.Errorf("dropped: %v", sk.entries)
	}
	note := sk.note("the CLI's host --raw")
	if !strings.Contains(note, "byname{}.n (1)") || !strings.Contains(note, "left out whole") || !strings.Contains(note, "items[].id (1)") ||
		!strings.Contains(note, "not as zero, false or empty") || !strings.Contains(note, "host --raw") {
		t.Errorf("note: %s", note)
	}
	for _, leak := range []string{"secret", "k2", "443", `"80"`, "true", "ssh"} {
		if strings.Contains(note, leak) {
			t.Errorf("the note carries a value or a key (%s): %s", leak, note)
		}
	}
}

// On a well-formed document decodeLoose and encoding/json agree, including
// on keys that repeat or differ only in case: the later one in document order
// wins, and a repeated object is merged.
func TestDecodeLooseMatchesStrictDecoding(t *testing.T) {
	search := `{"total": 2, "matches": [{"ip_str": "1.2.3.4", "port": 443, "transport": "tcp", "org": "Example",
	  "location": {"country_code": "JP"}, "http": {"status": 200, "title": "A"}, "vulns": {"CVE-2000-0001": {"cvss": 5.0, "verified": true}}}],
	  "facets": {"port": [{"count": 9, "value": 443}]}}`
	dup := `{"port": 1, "PORT": 2, "name": "a", "Name": "b", "inner": {"n": 1}, "inner": {"tags": ["x"]}, "byname": {"a": {"n": 1}}, "byname": {"b": {"n": 2}}}`
	for _, c := range []struct {
		doc         string
		strict, lse any
	}{
		{hostFixture, &wireHost{}, &wireHost{}},
		{search, &searchWire{}, &searchWire{}},
		{dup, &looseDoc{}, &looseDoc{}},
	} {
		if err := json.Unmarshal([]byte(c.doc), c.strict); err != nil {
			t.Fatal(err)
		}
		sk, err := decodeLoose([]byte(c.doc), c.lse)
		if err != nil || len(sk.values)+len(sk.entries) != 0 {
			t.Fatalf("sk %v err %v", sk, err)
		}
		a, _ := json.Marshal(c.strict)
		b, _ := json.Marshal(c.lse)
		if string(a) != string(b) {
			t.Errorf("loose and strict decoding differ:\n%s\n%s", a, b)
		}
		if sk.note("x") != "" {
			t.Error("a note for nothing left out")
		}
	}
}

func TestDecodeLooseRefusesOnlyANonObject(t *testing.T) {
	for _, in := range []string{`[]`, `"x"`, `null`, `1`, `{`, ``, `{} {}`, `{"a": }`, `{"a":1}x`, `{"a":1} 2`} {
		var w wireHost
		if _, err := decodeLoose([]byte(in), &w); err == nil {
			t.Errorf("%q was accepted", in)
		}
	}
	var w wireHost
	if sk, err := decodeLoose([]byte(`{"data": "x", "ports": {}}`), &w); err != nil || sk.values["data"] != 1 || sk.values["ports"] != 1 {
		t.Errorf("sk %v err %v", sk, err)
	}
}

// driftedHost is hostFixture with a value of another type in every kind of
// place the projection reads: a number as a string, a bool as a string, an
// object where a string is, a list element of another type, and a service
// whose port cannot be read.
func driftedHost() string {
	r := strings.NewReplacer(
		`"cvss": 5.0,`, `"cvss": "5.0",`,
		`"verified": true`, `"verified": "true"`,
		`{"status": 200,`, `{"status": "200",`,
		`"hash": -123456`, `"hash": "-123456"`,
		`"ports": [443, 22, 53]`, `"ports": [443, "22", 53]`,
		`"title": "Welcome"`, `"title": {"text": "Welcome"}`,
		`{"port": 22, "transport": "tcp"`, `{"port": "22", "transport": "tcp"`,
	)
	return r.Replace(hostFixture)
}

func TestAHostRecordWithDriftedValuesReadsAndNamesWhatWasLeftOut(t *testing.T) {
	up := newFake()
	body := driftedHost()
	if strings.Count(body, `"22"`) != 2 {
		t.Fatal("the replacements did not apply")
	}
	up.hosts["1.2.3.4"] = body
	e := testEngine(t, up)
	h, err := e.LookupHost(context.Background(), "1.2.3.4", false)
	if err != nil {
		t.Fatal(err)
	}
	// The service whose port cannot be read is left out — never shown as
	// port 0 — and its CVE still counts from the host's own list.
	if h.ServiceCount != 3 || h.VulnCount != 3 || h.ASN != "AS64500" {
		t.Errorf("host: services %d vulns %d asn %q", h.ServiceCount, h.VulnCount, h.ASN)
	}
	for _, s := range h.Services {
		if s.Port == 0 {
			t.Errorf("a service with port 0: %+v", s)
		}
	}
	for _, v := range h.Vulns {
		for _, p := range v.Ports {
			if p == 0 {
				t.Errorf("a CVE on port 0: %+v", v)
			}
		}
	}
	https := h.Services[2]
	if https.Port != 443 || https.Product != "ExampleServer" || https.HTTP == nil || https.HTTP.Status != nil || https.HTTP.Title != "" || https.HTTP.Server != "ExampleServer" {
		t.Errorf("https: %+v / %+v", https, https.HTTP)
	}
	if len(h.Ports) != 2 {
		t.Errorf("ports: %v", h.Ports)
	}
	notes := strings.Join(h.Notes, " ")
	for _, p := range []string{"ports[] (1)", "data[].http.status (1)", "data[].http.title (1)", "data[].http.favicon.hash (1)",
		"data[].vulns{}.cvss (1)", "left out whole", "data[].port (1)", "host --raw"} {
		if !strings.Contains(notes, p) {
			t.Errorf("notes lack %q: %s", p, notes)
		}
	}
	if strings.Contains(notes, "Welcome") {
		t.Errorf("a value reached the notes: %s", notes)
	}
	// The raw record and the cache are not lost to the drift.
	var compact bytes.Buffer
	_ = json.Compact(&compact, []byte(body))
	raw, _, err := e.Raw(context.Background(), "1.2.3.4", false)
	if err != nil || string(raw) != compact.String() {
		t.Errorf("raw: %v", err)
	}
	if up.count("host") != 1 {
		t.Errorf("the record was not cached (fetches %d)", up.count("host"))
	}
	p, err := e.GetService(context.Background(), ServiceQuery{IP: "1.2.3.4", Port: 443, Section: SectionHTML}, false)
	if err != nil || !strings.Contains(strings.Join(p.Notes, " "), "data[].http.status") {
		t.Errorf("service: %v %v", err, p)
	}
	// The port whose service was left out is not reported as unobserved.
	_, err = e.GetService(context.Background(), ServiceQuery{IP: "1.2.3.4", Port: 22, Section: SectionBanner}, false)
	if Code(err) == CodeNotObserved || !strings.Contains(err.Error(), "may be this one") {
		t.Errorf("port 22: %v", err)
	}
}

// Services that are not a list are a changed API, not drift: refused before
// the cache, as a search page without a list of matches is.
func TestAHostRecordWhoseServicesAreNotAListIsRefused(t *testing.T) {
	up := newFake()
	up.hosts["1.2.3.4"] = `{"ip_str": "1.2.3.4", "data": {"port": 22}}`
	e := testEngine(t, up)
	_, err := e.LookupHost(context.Background(), "1.2.3.4", false)
	wantCode(t, err, shodan.CodeDecode)
	_, _ = e.LookupHost(context.Background(), "1.2.3.4", false)
	if up.count("host") != 2 {
		t.Errorf("the record was cached (fetches %d)", up.count("host"))
	}
	up.hosts["1.2.3.4"] = `{"ip_str": "1.2.3.4"}`
	if h, err := e.LookupHost(context.Background(), "1.2.3.4", false); err != nil || h.ServiceCount != 0 {
		t.Errorf("a record without services: %v", err)
	}
}

func TestAHistoryWithADriftedBannerKeepsTheRest(t *testing.T) {
	up := newFake()
	body := historyBody(10)
	body = strings.Replace(body, `"title":"New"`, `"title":["New"]`, 1)
	body = strings.Replace(body, `"port":53,`, `"port":"53",`, 1)
	up.histories["1.2.3.4"] = body
	e := testEngine(t, up)
	h, err := e.GetHistory(context.Background(), HistoryQuery{IP: "1.2.3.4"}, false)
	if err != nil {
		t.Fatal(err)
	}
	// The window counts what Shodan returned, the banner left out included.
	if h.Window.Banners != 14 {
		t.Errorf("banners: %d", h.Window.Banners)
	}
	for _, p := range h.Ports {
		if p.Port == 0 {
			t.Errorf("a port 0 bucket: %+v", p)
		}
	}
	notes := strings.Join(h.Notes, " ")
	if !strings.Contains(notes, "data[].port (1)") || !strings.Contains(notes, "data[].http.title (1)") || !strings.Contains(notes, "history --raw") ||
		!strings.Contains(notes, "1 banner(s) had no readable port or transport") || !strings.Contains(notes, "Shodan returned 14 banners") {
		t.Errorf("notes: %s", notes)
	}
	if raw, err := e.RawHistory(context.Background(), "1.2.3.4", false); err != nil || string(raw) != body {
		t.Errorf("raw history: %v", err)
	}
}

func TestAPaidForPageWithADriftedMatchIsDeliveredAndCached(t *testing.T) {
	up := creditFake(50, 1)
	up.searchBody = `{"total": 3, "matches": [
	  {"ip_str": "1.2.3.4", "port": 443, "transport": "tcp", "http": {"status": "200", "title": "A"}},
	  {"ip_str": "1.2.3.5", "port": 22, "transport": "tcp", "vulns": {"CVE-2000-0001": "high"}},
	  {"ip_str": "1.2.3.6", "port": [8080], "transport": "tcp"},
	  {"ip_str": 7, "port": 80, "transport": "tcp"}],
	  "facets": {"port": [{"count": "9", "value": 443}, {"count": 3, "value": 22}]}}`
	e := searchEngine(t, up, 0)
	q := SearchQuery{Query: "port:443", Facets: []FacetSpec{{Name: "port", N: 5}}}
	s, err := e.SearchServices(context.Background(), q, false)
	if err != nil {
		t.Fatal(err)
	}
	// The CVE whose entry is unreadable still counts by its ID; the matches
	// without a readable port or address are left out, not shown as port 0
	// or an empty address.
	if len(s.Rows) != 2 || s.Rows[0].Title != "A" || s.Rows[1].VulnCount != 1 {
		t.Errorf("rows: %+v", s.Rows)
	}
	// A facet value whose count cannot be read is left out, not counted 0.
	if len(s.Facets) != 1 || len(s.Facets[0].Values) != 1 || s.Facets[0].Values[0].Count != 3 {
		t.Errorf("facets: %+v", s.Facets)
	}
	notes := strings.Join(s.Notes, " ")
	for _, p := range []string{"matches[].http.status (1)", "matches[].vulns{} (1)", "matches[].port (1)", "matches[].ip_str (1)", "facets{}[].count (1)", "search --raw"} {
		if !strings.Contains(notes, p) {
			t.Errorf("notes lack %q: %s", p, notes)
		}
	}
	if _, err := e.SearchServices(context.Background(), q, false); err != nil || up.count("search") != 1 {
		t.Errorf("the page was not cached: %v (searches %d)", err, up.count("search"))
	}
}

// A count is read the same way, and a body the gate accepts is never an
// error once cached.
func TestACountWithADriftedFacetIsAnswered(t *testing.T) {
	up := newFake()
	up.countRaw["port:22|port:3"] = `{"total": 120, "facets": {"port": [{"count": "100", "value": 22}, {"count": 7, "value": 2222}]}}`
	e := testEngine(t, up)
	for i := range 2 {
		c, err := e.CountServices(context.Background(), "port:22", []FacetSpec{{Name: "port", N: 3}}, false)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if c.Total != 120 || len(c.Facets[0].Values) != 1 || c.Facets[0].Values[0].Count != 7 {
			t.Errorf("count: %+v", c)
		}
		if !strings.Contains(strings.Join(c.Notes, " "), "facets{}[].count (1)") {
			t.Errorf("notes: %v", c.Notes)
		}
	}
	if up.count("count") != 1 {
		t.Errorf("counts sent: %d", up.count("count"))
	}
	up.countRaw["port:23|"] = `{"total": "120"}`
	_, err := e.CountServices(context.Background(), "port:23", nil, false)
	wantCode(t, err, shodan.CodeDecode)
}

// A required field that is missing or null is as unknown as one of the wrong
// type, and an entry that is null or not an object is no entry: each is left
// out whole, never kept with a zero.
func TestAnEntryWithoutItsIdentityIsLeftOut(t *testing.T) {
	var d looseDoc
	sk, err := decodeLoose([]byte(`{"items": [{"id": null, "name": "a"}, {"name": "b"}, null, "x", {"id": 4}]}`), &d)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Items) != 1 || d.Items[0].ID != 4 {
		t.Errorf("items: %+v", d.Items)
	}
	if sk.dropped("items[]") != 4 || sk.entries["items[].id"] != 2 || sk.entries["items[]"] != 2 || len(sk.values) != 0 {
		t.Errorf("skipped: %+v", sk)
	}
}

// As in encoding/json, the last occurrence of a key decides: an unreadable
// earlier duplicate does not cost the entry, an unreadable later one does.
func TestTheLastOccurrenceOfARequiredFieldDecides(t *testing.T) {
	var d looseDoc
	sk, err := decodeLoose([]byte(`{"items": [{"id": "x", "id": 1}, {"id": 2, "ID": "y"}]}`), &d)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Items) != 1 || d.Items[0].ID != 1 || sk.entries["items[].id"] != 1 || len(sk.values) != 0 {
		t.Errorf("items %+v skipped %+v", d.Items, sk)
	}
}

func TestHostServicesWithoutAPortAreLeftOut(t *testing.T) {
	up := newFake()
	up.hosts["1.2.3.4"] = `{"ip_str": "1.2.3.4", "ports": [22, 443], "data": [null,
	  {"port": null, "transport": "tcp", "data": "a"}, {"transport": "tcp", "data": "b"},
	  {"port": 22, "transport": "tcp", "data": "SSH-2.0-x"}]}`
	e := testEngine(t, up)
	h, err := e.LookupHost(context.Background(), "1.2.3.4", false)
	if err != nil {
		t.Fatal(err)
	}
	if h.ServiceCount != 1 || h.Services[0].Port != 22 {
		t.Errorf("services: %+v", h.Services)
	}
	notes := strings.Join(h.Notes, " ")
	if !strings.Contains(notes, "data[] (1)") || !strings.Contains(notes, "data[].port (2)") {
		t.Errorf("notes: %s", notes)
	}
	_, err = e.GetService(context.Background(), ServiceQuery{IP: "1.2.3.4", Port: 443, Section: SectionBanner}, false)
	if Code(err) == CodeNotObserved {
		t.Errorf("443 manufactured as not observed: %v", err)
	}
}

func TestAFacetValueWithoutACountIsLeftOut(t *testing.T) {
	up := newFake()
	up.countRaw["port:22|port:5"] = `{"total": 10, "facets": {"port": [{"count": null, "value": 1}, {"value": 2}, null, {"count": 4, "value": 22}]}}`
	c, err := testEngine(t, up).CountServices(context.Background(), "port:22", []FacetSpec{{Name: "port", N: 5}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if v := c.Facets[0].Values; len(v) != 1 || v[0].Count != 4 || v[0].Value != "22" {
		t.Errorf("values: %+v", v)
	}
}

// A capped history stays capped when a banner in it cannot be read: the cap
// is on what Shodan returned.
func TestACappedHistoryWithALeftOutBannerIsStillCapped(t *testing.T) {
	up := newFake()
	up.histories["1.2.3.4"] = strings.Replace(historyBody(HistoryCap-4), `"port":53,`, `"port":"53",`, 1)
	h, err := testEngine(t, up).GetHistory(context.Background(), HistoryQuery{IP: "1.2.3.4"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if h.Window.Banners != HistoryCap || !h.Window.Capped {
		t.Errorf("window: %+v", h.Window)
	}
	notes := strings.Join(h.Notes, " ")
	if !strings.Contains(notes, "nothing earlier can be read") || strings.Contains(notes, "under its") {
		t.Errorf("notes: %s", notes)
	}
}
