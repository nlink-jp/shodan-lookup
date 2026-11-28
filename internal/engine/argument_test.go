package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/nlink-jp/shodan-lookup/internal/ipaddr"
	"github.com/nlink-jp/shodan-lookup/internal/shodan"
)

const sha256Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// Every refusal of the input says which tool argument it is about, so the MCP
// layer can name it (ADR-0002); its code and message are what the CLI shows,
// unchanged.
func TestEveryArgumentRefusalNamesItsArgument(t *testing.T) {
	ctx := context.Background()
	up := newFake()
	// Shodan's own refusal of an address the local gate let through.
	up.hostErr["1.2.3.5"] = &shodan.Error{Code: shodan.CodeUpstream, Status: 404, APIError: "Invalid IP"}
	// A history with port 53 on both transports.
	up.histories["1.2.3.4"] = `{"ip_str":"1.2.3.4","ports":[53,443],"data":[` +
		`{"port":53,"transport":"udp","timestamp":"2026-10-07T01:00:00.000000","data":"u","_shodan":{"module":"dns-udp"}},` +
		`{"port":53,"transport":"tcp","timestamp":"2026-10-07T02:00:00.000000","data":"t","_shodan":{"module":"dns-tcp"}},` +
		`{"port":443,"transport":"tcp","timestamp":"2026-10-07T03:00:00.000000","data":"h","_shodan":{"module":"https"}}]}`
	e := testEngine(t, up)
	host := func(ip string) func() error {
		return func() error { _, err := e.LookupHost(ctx, ip, false); return err }
	}
	history := func(q HistoryQuery) func() error {
		return func() error { _, err := e.GetHistory(ctx, q, false); return err }
	}
	service := func(q ServiceQuery) func() error {
		return func() error { _, err := e.GetService(ctx, q, false); return err }
	}
	count := func(query string, facets ...FacetSpec) func() error {
		return func() error { _, err := e.CountServices(ctx, query, facets, false); return err }
	}
	facet := func(s string) func() error {
		return func() error { _, err := ParseFacet(s); return err }
	}
	search := func(q SearchQuery) func() error {
		return func() error { _, err := e.SearchServices(ctx, q, false); return err }
	}
	cases := []struct {
		name string
		run  func() error
		arg  string
	}{
		{"an internal ip", host("10.0.0.1"), "ip"},
		{"a hostname", host("example.com"), "ip"},
		{"an address Shodan refuses", host("1.2.3.5"), "ip"},
		{"history of an internal ip", history(HistoryQuery{IP: "192.168.0.1"}), "ip"},
		{"history port out of range", history(HistoryQuery{IP: "1.2.3.4", Port: 70000}), "port"},
		{"history transport", history(HistoryQuery{IP: "1.2.3.4", Port: 22, Transport: "sctp"}), "transport"},
		{"history offset", history(HistoryQuery{IP: "1.2.3.4", Port: 22, Offset: -1}), "offset"},
		{"history limit", history(HistoryQuery{IP: "1.2.3.4", Port: 22, Limit: MaxListLimit + 1}), "limit"},
		{"history of a port on two transports", history(HistoryQuery{IP: "1.2.3.4", Port: 53}), "transport"},
		{"history offset past the end", history(HistoryQuery{IP: "1.2.3.4", Port: 443, Offset: 100}), "offset"},
		{"service section", service(ServiceQuery{IP: "1.2.3.4", Port: 22, Section: "nope"}), "section"},
		{"service port", service(ServiceQuery{IP: "1.2.3.4", Section: SectionBanner}), "port"},
		{"service transport", service(ServiceQuery{IP: "1.2.3.4", Port: 22, Transport: "x", Section: SectionBanner}), "transport"},
		{"service offset", service(ServiceQuery{IP: "1.2.3.4", Port: 22, Offset: -1, Section: SectionBanner}), "offset"},
		{"service text limit", service(ServiceQuery{IP: "1.2.3.4", Port: 22, Limit: MaxTextLimit + 1, Section: SectionBanner}), "limit"},
		{"service offset past the end", service(ServiceQuery{IP: "1.2.3.4", Port: 22, Offset: 1 << 20, Section: SectionBanner}), "offset"},
		{"a service port on two transports", service(ServiceQuery{IP: "1.2.3.4", Port: 53, Section: SectionBanner}), "transport"},
		{"a list section's limit", service(ServiceQuery{IP: "1.2.3.4", Port: 443, Limit: MaxListLimit + 1, Section: SectionVulns}), "limit"},
		{"a list section's offset past the end", service(ServiceQuery{IP: "1.2.3.4", Port: 443, Offset: 1 << 20, Section: SectionVulns}), "offset"},
		{"an internal address in a query", count("net:10.0.0.0/8"), "query"},
		{"an unclosed quote", count(`http.title:"x`), "query"},
		{"an unknown filter", count("nosuchfilter:x"), "query"},
		{"a SHA-256 fingerprint", count("ssl.cert.fingerprint:" + sha256Hex), "query"},
		{"an unknown facet", count("port:22", FacetSpec{Name: "nosuchfacet", N: 5}), "facets"},
		{"a facet asked twice", count("port:22", FacetSpec{Name: "org", N: 5}, FacetSpec{Name: "org", N: 5}), "facets"},
		{"a facet without a name", facet(":5"), "facets"},
		{"a facet count out of range", facet("org:1001"), "facets"},
		{"an empty query to parse", func() error { _, err := e.ParseQuery(ctx, ""); return err }, "query"},
		{"a search page out of range", search(SearchQuery{Query: "port:22", Page: MaxSearchPage + 1}), "page"},
		{"a search with an internal address", search(SearchQuery{Query: "ip:127.0.0.1"}), "query"},
	}
	for _, c := range cases {
		err := c.run()
		if Code(err) != CodeInvalidArgument {
			t.Errorf("%s: code %q (%v), want %q", c.name, Code(err), err, CodeInvalidArgument)
			continue
		}
		if got := Argument(err); got != c.arg {
			t.Errorf("%s: argument %q (%v), want %q", c.name, got, err, c.arg)
		}
	}
}

// A refusal of the input gate keeps the gate's error and message: the CLI
// reads both as before.
func TestAGateRefusalKeepsTheGateError(t *testing.T) {
	_, err := testEngine(t, newFake()).LookupHost(context.Background(), "10.0.0.1", false)
	var ie *ipaddr.Error
	if !errors.As(err, &ie) || err.Error() != ie.Error() {
		t.Errorf("err = %v (%T); the *ipaddr.Error is not kept as it was", err, err)
	}
}

// Errors that are not about an argument name none.
func TestOtherErrorsNameNoArgument(t *testing.T) {
	if got := Argument(&Error{Code: CodeNotIndexed, Message: "x"}); got != "" {
		t.Errorf("not_indexed names %q", got)
	}
	if got := Argument(errors.New("plain")); got != "" {
		t.Errorf("a plain error names %q", got)
	}
}
