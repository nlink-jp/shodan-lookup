package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type looseInner struct {
	N    *int     `json:"n"`
	Tags []string `json:"tags"`
}

type looseEmbedded struct {
	Port int `json:"port"`
}

type looseDoc struct {
	looseEmbedded
	Name   string                  `json:"name"`
	Ports  []int                   `json:"ports"`
	Inner  *looseInner             `json:"inner"`
	Byname map[string]looseInner   `json:"byname"`
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
	if _, ok := d.Byname["k2"]; ok || d.Byname["k1"].N == nil || *d.Byname["k1"].N != 1 || d.Byname["k3"].N != nil {
		t.Errorf("byname: %+v", d.Byname)
	}
	if d.Gone != "" || d.hidden != "" {
		t.Errorf("an ignored field was set: %+v", d)
	}
	want := map[string]int{"port": 1, "ports[]": 1, "inner.n": 1, "inner.tags[]": 1, "byname{}": 1, "byname{}.n": 1}
	if len(sk) != len(want) {
		t.Errorf("skipped = %v, want %v", sk, want)
	}
	for p, n := range want {
		if sk[p] != n {
			t.Errorf("skipped[%q] = %d, want %d (all: %v)", p, sk[p], n, sk)
		}
	}
	note := sk.note("the CLI's host --raw")
	if !strings.Contains(note, "6 value(s)") || !strings.Contains(note, "byname{}.n (1)") || !strings.Contains(note, "host --raw") {
		t.Errorf("note: %s", note)
	}
	for _, leak := range []string{"secret", "k2", "443", `"80"`, "true"} {
		if strings.Contains(note, leak) {
			t.Errorf("the note carries a value or a key (%s): %s", leak, note)
		}
	}
}

func TestDecodeLooseMatchesStrictDecodingOnAWellFormedDocument(t *testing.T) {
	var strict, loose wireHost
	if err := json.Unmarshal([]byte(hostFixture), &strict); err != nil {
		t.Fatal(err)
	}
	sk, err := decodeLoose([]byte(hostFixture), &loose)
	if err != nil || len(sk) != 0 {
		t.Fatalf("sk %v err %v", sk, err)
	}
	a, _ := json.Marshal(strict)
	b, _ := json.Marshal(loose)
	if string(a) != string(b) {
		t.Errorf("loose and strict decoding differ:\n%s\n%s", a, b)
	}
	if sk.note("x") != "" {
		t.Error("a note for nothing left out")
	}
}

func TestDecodeLooseRefusesOnlyANonObject(t *testing.T) {
	for _, in := range []string{`[]`, `"x"`, `null`, `1`, `{`, ``} {
		var w wireHost
		if _, err := decodeLoose([]byte(in), &w); err == nil {
			t.Errorf("%q was accepted", in)
		}
	}
	var w wireHost
	if sk, err := decodeLoose([]byte(`{"data": "x", "ports": {}}`), &w); err != nil || sk["data"] != 1 || sk["ports"] != 1 {
		t.Errorf("sk %v err %v", sk, err)
	}
}

// driftedHost is hostFixture with a value of another type in every kind of
// place the projection reads: a number as a string, a bool as a string, an
// object where a string is, a list element of another type.
func driftedHost() string {
	r := strings.NewReplacer(
		`"cvss": 5.0,`, `"cvss": "5.0",`,
		`"verified": true`, `"verified": "true"`,
		`{"status": 200,`, `{"status": "200",`,
		`"hash": -123456`, `"hash": "-123456"`,
		`"ports": [443, 22, 53]`, `"ports": [443, "22", 53]`,
		`"title": "Welcome"`, `"title": {"text": "Welcome"}`,
	)
	return r.Replace(hostFixture)
}

func TestAHostRecordWithDriftedValuesReadsAndNamesWhatWasLeftOut(t *testing.T) {
	up := newFake()
	body := driftedHost()
	if body == hostFixture {
		t.Fatal("the replacements did not apply")
	}
	up.hosts["1.2.3.4"] = body
	e := testEngine(t, up)
	h, err := e.LookupHost(context.Background(), "1.2.3.4", false)
	if err != nil {
		t.Fatal(err)
	}
	if h.ServiceCount != 4 || h.VulnCount != 3 || h.ASN != "AS64500" {
		t.Errorf("host: services %d vulns %d asn %q", h.ServiceCount, h.VulnCount, h.ASN)
	}
	https := h.Services[3]
	if https.Product != "ExampleServer" || https.HTTP == nil || https.HTTP.Status != nil || https.HTTP.Title != "" || https.HTTP.Server != "ExampleServer" {
		t.Errorf("https: %+v / %+v", https, https.HTTP)
	}
	if len(h.Ports) != 2 {
		t.Errorf("ports: %v", h.Ports)
	}
	notes := strings.Join(h.Notes, " ")
	for _, p := range []string{"ports[] (1)", "data[].http.status (1)", "data[].http.title (1)", "data[].http.favicon.hash (1)",
		"data[].vulns{}.cvss (1)", "data[].vulns{}.verified (1)", "host --raw"} {
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
	if h.Window.Banners != 14 {
		t.Errorf("banners: %d", h.Window.Banners)
	}
	notes := strings.Join(h.Notes, " ")
	if !strings.Contains(notes, "data[].port (1)") || !strings.Contains(notes, "data[].http.title (1)") || !strings.Contains(notes, "history --raw") {
		t.Errorf("notes: %s", notes)
	}
	if raw, err := e.RawHistory(context.Background(), "1.2.3.4", false); err != nil || string(raw) != body {
		t.Errorf("raw history: %v", err)
	}
}

func TestAPaidForPageWithADriftedMatchIsDeliveredAndCached(t *testing.T) {
	up := creditFake(50, 1)
	up.searchBody = `{"total": 2, "matches": [
	  {"ip_str": "1.2.3.4", "port": 443, "transport": "tcp", "http": {"status": "200", "title": "A"}},
	  {"ip_str": "1.2.3.5", "port": 22, "transport": "tcp", "vulns": {"CVE-2000-0001": {"cvss": "high"}}}],
	  "facets": {"port": [{"count": "9", "value": 443}, {"count": 3, "value": 22}]}}`
	e := searchEngine(t, up, 0)
	q := SearchQuery{Query: "port:443", Facets: []FacetSpec{{Name: "port", N: 5}}}
	s, err := e.SearchServices(context.Background(), q, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Rows) != 2 || s.Rows[0].Title != "A" || s.Rows[1].VulnCount != 1 {
		t.Errorf("rows: %+v", s.Rows)
	}
	if len(s.Facets) != 1 || len(s.Facets[0].Values) != 2 || s.Facets[0].Values[0].Count != 0 {
		t.Errorf("facets: %+v", s.Facets)
	}
	notes := strings.Join(s.Notes, " ")
	if !strings.Contains(notes, "matches[].http.status (1)") || !strings.Contains(notes, "facets{}[].count (1)") || !strings.Contains(notes, "search --raw") {
		t.Errorf("notes: %s", notes)
	}
	if _, err := e.SearchServices(context.Background(), q, false); err != nil || up.count("search") != 1 {
		t.Errorf("the page was not cached: %v (searches %d)", err, up.count("search"))
	}
}
