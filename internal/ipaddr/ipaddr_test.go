package ipaddr

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// One row per table row and per embedding: a class is a table row plus a test
// row. TestEveryRowIsExercised holds the two lists to each other.
var refusedCases = []struct {
	addr  string
	class Class
	via   string
}{
	{"0.1.2.3", ClassReserved, ""},
	{"10.20.30.40", ClassPrivate, ""},
	{"100.64.0.1", ClassShared, ""},
	{"127.0.0.1", ClassLoopback, ""},
	{"169.254.169.254", ClassLinkLocal, ""},
	{"172.16.5.4", ClassPrivate, ""},
	{"192.0.0.8", ClassReserved, ""},
	{"192.0.2.1", ClassDocumentation, ""},
	{"192.168.1.1", ClassPrivate, ""},
	{"198.18.0.1", ClassReserved, ""},
	{"198.51.100.7", ClassDocumentation, ""},
	{"203.0.113.9", ClassDocumentation, ""},
	{"224.0.0.251", ClassMulticast, ""},
	{"240.0.0.1", ClassReserved, ""},
	{"100::1", ClassReserved, ""},
	{"2001:2::1", ClassReserved, ""},
	{"2001:db8::1", ClassDocumentation, ""},
	{"3fff::1", ClassDocumentation, ""},
	{"fd00::1", ClassUniqueLocal, ""},
	{"fe80::1", ClassLinkLocal, ""},
	{"fec0::1", ClassSiteLocal, ""},
	{"ff02::1", ClassMulticast, ""},
	{"0.0.0.0", ClassUnspecified, ""},
	{"255.255.255.255", ClassBroadcast, ""},
	{"::", ClassUnspecified, ""},
	{"::1", ClassLoopback, ""},
	{"64:ff9b::a00:1", ClassPrivate, "nat64"},
	{"64:ff9b:1::c0a8:101", ClassPrivate, "nat64-local"},
	{"2002:c0a8:0101::1", ClassPrivate, "6to4"},
	{"2001:0:4136:e378:8000:63bf:f5ff:fffe", ClassPrivate, "teredo"}, // client 10.0.0.1, bits inverted
	{"::a00:1", ClassPrivate, "ipv4-compatible"},
}

func TestRefusedClasses(t *testing.T) {
	for _, tc := range refusedCases {
		c, via := Classify(netip.MustParseAddr(tc.addr))
		if c != tc.class || via != tc.via {
			t.Errorf("%s: Classify = (%q, %q), want (%q, %q)", tc.addr, c, via, tc.class, tc.via)
		}
	}
}

func TestEveryRowIsExercised(t *testing.T) {
	for _, r := range table {
		hit := false
		for _, tc := range refusedCases {
			if tc.via == "" && r.prefix.Contains(netip.MustParseAddr(tc.addr)) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("table row %s has no test case", r.prefix)
		}
	}
	for _, e := range embeds {
		hit := false
		for _, tc := range refusedCases {
			hit = hit || tc.via == e.name
		}
		if !hit {
			t.Errorf("embedding %s has no test case", e.name)
		}
	}
}

func TestPublicAddressesPass(t *testing.T) {
	for in, want := range map[string]string{
		"8.8.8.8":                     "8.8.8.8",
		" 1.1.1.1 ":                   "1.1.1.1",
		"::ffff:9.9.9.9":              "9.9.9.9", // unmapped
		"2001:4860:4860::8888":        "2001:4860:4860::8888",
		"2001:4860:4860:0:0:0:0:8888": "2001:4860:4860::8888", // canonical form is sent
		"2002:0808:0808::1":           "2002:808:808::1",      // 6to4 of a public address
		"64:ff9b::808:808":            "64:ff9b::808:808",     // NAT64 of a public address
		"2a00:1450:4001:80b::200e":    "2a00:1450:4001:80b::200e",
		"126.7.81.203":                "126.7.81.203",
		"191.255.255.255":             "191.255.255.255",
		"192.0.3.0":                   "192.0.3.0",
		"198.20.0.1":                  "198.20.0.1",
		"223.255.255.255":             "223.255.255.255",
	} {
		got, err := Parse(in)
		if err != nil {
			t.Errorf("%q: refused: %v", in, err)
			continue
		}
		if got.String() != want {
			t.Errorf("%q: canonical form %s, want %s", in, got, want)
		}
	}
}

func TestParseRefusesWhatCannotBeSent(t *testing.T) {
	for in, want := range map[string]string{
		"008.008.008.008":   "not an IP address", // upstream answers 500 (measured)
		"8.8.8":             "not an IP address",
		"example.com":       "doh-lookup",
		"fe80::1%en0":       "zoned",
		"":                  "not an IP address",
		"10.0.0.1":          "private",
		"::ffff:10.0.0.1":   "private",
		"2002:0a00:0001::1": "inside 6to4",
	} {
		_, err := Parse(in)
		var e *Error
		if !errors.As(err, &e) {
			t.Errorf("%q: error %v is not an *Error", in, err)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %q does not mention %q", in, err, want)
		}
	}
}

func TestCheckPrefix(t *testing.T) {
	for _, ok := range []string{"8.8.8.0/24", "8.0.0.0/7", "2001:4860::/32", "1.1.1.1/32"} {
		if _, err := CheckPrefix(ok); err != nil {
			t.Errorf("%s: refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"10.0.0.0/8", "10.1.2.0/24", "192.168.1.128/25", "0.0.0.0/0", "::/0",
		"fd00::/8", "2002:0a00::/24", "1.2.3.4", "not-a-cidr", "192.168.1.5/16"} {
		if _, err := CheckPrefix(bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

func TestLexSplitsOutsideQuotes(t *testing.T) {
	terms, err := Lex(`apache http.title:"Login page" -port:22 "Server: nginx" country:JP`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Term{
		{Raw: "apache"},
		{Raw: `http.title:"Login page"`, Filter: "http.title", Value: "Login page"},
		{Raw: "-port:22", Negated: true, Filter: "port", Value: "22"},
		{Raw: `"Server: nginx"`},
		{Raw: "country:JP", Filter: "country", Value: "JP"},
	}
	if len(terms) != len(want) {
		t.Fatalf("terms = %+v", terms)
	}
	for i := range want {
		if terms[i] != want[i] {
			t.Errorf("term %d = %+v, want %+v", i, terms[i], want[i])
		}
	}
}

func TestLexRefusesWhatUpstreamWouldMisread(t *testing.T) {
	for _, q := range []string{"", "   ", `port:"`, `http.title:"unterminated`, strings.Repeat("a", MaxQueryLen+1)} {
		if _, err := Lex(q); err == nil {
			t.Errorf("%q: accepted", q)
		}
	}
}

func TestCheckQueryJudgesIPAndNetValues(t *testing.T) {
	for _, ok := range []string{
		"port:22 country:JP",
		"ip:8.8.8.8",
		"net:8.8.8.0/24,1.1.1.0/24",
		"-net:8.8.0.0/16 port:443",
		"ip:2001:4860:4860::8888",
		`hostname:"intranet.example.test"`, // names cannot be judged — the documented residual
	} {
		if _, err := CheckQuery(ok); err != nil {
			t.Errorf("%q: refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"ip:10.0.0.1",
		"IP:10.0.0.1",
		"port:22 net:192.168.0.0/16",
		"net:8.8.8.0/24,10.0.0.0/8",
		"-net:172.16.0.0/12",
		`net:"10.0.0.0/8"`,
		"ip:fe80::1",
		"ip:not-an-ip",
		"net:10.0.0.0",
	} {
		if _, err := CheckQuery(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}
