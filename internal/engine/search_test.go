package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/nlink-jp/shodan-lookup/internal/shodan"
)

func creditFake(credits, charge int) *fakeUp {
	up := newFake()
	up.credits, up.charge = &credits, charge
	return up
}

func searchEngine(t *testing.T, up *fakeUp, floor int) *Engine {
	t.Helper()
	e := testEngine(t, up)
	e.cfg.CreditFloor = floor
	return e
}

func TestASearchSpendsWhatWasPredictedAndSaysSo(t *testing.T) {
	up := creditFake(50, 1)
	s, err := searchEngine(t, up, 20).SearchServices(context.Background(), SearchQuery{Query: "port:443 country:JP",
		Facets: []FacetSpec{{Name: "country", N: 3}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	c := s.Credits
	if c == nil || c.Predicted != 1 || c.Before != 50 || *c.After != 49 || *c.Spent != 1 || c.Floor != 20 {
		t.Errorf("credits: %+v", c)
	}
	if s.Total != 2 || len(s.Rows) != 2 || s.Rows[0].IP != "1.2.3.4" || s.Rows[0].Title != "Welcome" || s.Rows[0].VulnCount != 1 ||
		s.Rows[0].Timestamp != "2026-10-09T05:00:00Z" || s.Rows[1].Transport != "udp" || s.Unit != "services" {
		t.Errorf("rows: %+v", s.Rows)
	}
	if len(s.Facets) != 1 || s.Facets[0].Values[0].Value != "JP" {
		t.Errorf("facets: %+v", s.Facets)
	}
	// The order of operations: gate and names, tokens, the read before, the
	// search, the read after.
	var order []string
	for _, c := range up.calls {
		order = append(order, strings.Fields(c)[0])
	}
	got := strings.Join(order, " ")
	if !strings.HasSuffix(got, "tokens apiinfo search apiinfo") {
		t.Errorf("call order: %s", got)
	}
}

// The floor is checked counting the search as one credit, even when the
// prediction is 0, and nothing is sent when it would be crossed.
func TestTheFloorIsCheckedAsIfEverySearchCostOne(t *testing.T) {
	for _, q := range []string{"port:443", "apache"} { // predicted 1 and 0
		up := creditFake(20, 0)
		_, err := searchEngine(t, up, 20).SearchServices(context.Background(), SearchQuery{Query: q}, false)
		wantCode(t, err, CodeCreditFloor)
		if up.count("search") != 0 {
			t.Errorf("%s: a search was sent below the floor", q)
		}
	}
	up := creditFake(21, 1)
	if _, err := searchEngine(t, up, 20).SearchServices(context.Background(), SearchQuery{Query: "port:443"}, false); err != nil {
		t.Errorf("a search leaving exactly the floor was refused: %v", err)
	}
}

// A search that spends other than predicted stops searching for the process;
// cached pages are still served.
func TestAMismatchStopsSearching(t *testing.T) {
	up := creditFake(50, 2) // predicted 1, spends 2
	e := searchEngine(t, up, 0)
	s, err := e.SearchServices(context.Background(), SearchQuery{Query: "port:443"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if *s.Credits.Spent != 2 || !strings.Contains(strings.Join(s.Notes, " "), "stopped") {
		t.Errorf("the mismatch is not stated: %+v %v", s.Credits, s.Notes)
	}
	_, err = e.SearchServices(context.Background(), SearchQuery{Query: "port:80"}, false)
	wantCode(t, err, CodeCreditMismatch)
	if _, err := e.SearchServices(context.Background(), SearchQuery{Query: "port:443"}, false); err != nil {
		t.Errorf("a cached page was refused after the halt: %v", err)
	}
	if up.count("search") != 1 {
		t.Errorf("searches sent: %d", up.count("search"))
	}

	// A free search that turns out to cost is a mismatch too.
	up = creditFake(50, 1)
	e = searchEngine(t, up, 0)
	_, _ = e.SearchServices(context.Background(), SearchQuery{Query: "apache"}, false)
	_, err = e.SearchServices(context.Background(), SearchQuery{Query: "nginx"}, false)
	wantCode(t, err, CodeCreditMismatch)
}

// Spending that cannot be read afterwards cannot be trusted either.
func TestAnUnreadableSpendStopsSearching(t *testing.T) {
	up := creditFake(50, 1)
	up.apiInfoErrAfter = 1 // the read before succeeds, the read after fails
	e := searchEngine(t, up, 0)
	s, err := e.SearchServices(context.Background(), SearchQuery{Query: "port:443"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if s.Credits.After != nil || s.Credits.Spent != nil {
		t.Errorf("an unread spend is reported: %+v", s.Credits)
	}
	up.apiInfoErrAfter = 0
	_, err = e.SearchServices(context.Background(), SearchQuery{Query: "port:80"}, false)
	wantCode(t, err, CodeCreditMismatch)
}

// Fail-closed: when tokens or the read before fails, nothing is sent.
func TestNothingIsSentWhenTheGuardCannotRun(t *testing.T) {
	up := creditFake(50, 1)
	up.tokensErr = &shodan.Error{Code: shodan.CodeBadRequest, Status: 400, Message: "Invalid search query"}
	_, err := searchEngine(t, up, 0).SearchServices(context.Background(), SearchQuery{Query: "port:443"}, false)
	wantCode(t, err, shodan.CodeBadRequest)

	up2 := creditFake(50, 1)
	up2.apiInfoErrAfter = -1
	up2.credits = nil
	up2.apiInfo = `{"oops": true}`
	_, err = searchEngine(t, up2, 0).SearchServices(context.Background(), SearchQuery{Query: "port:443"}, false)
	wantCode(t, err, shodan.CodeDecode)
	if up.count("search")+up2.count("search") != 0 {
		t.Error("a search was sent without a working guard")
	}
}

func TestACachedPageSpendsNothing(t *testing.T) {
	up := creditFake(50, 1)
	e := searchEngine(t, up, 0)
	q := SearchQuery{Query: "port:443", Page: 2}
	if _, err := e.SearchServices(context.Background(), q, false); err != nil {
		t.Fatal(err)
	}
	s, err := e.SearchServices(context.Background(), q, false)
	if err != nil || !s.Provenance.Cached || s.Credits != nil || *up.credits != 49 {
		t.Errorf("cached page: %+v %v, credits left %d", s, err, *up.credits)
	}
	if up.count("search") != 1 || up.count("tokens") != 1 {
		t.Errorf("a cached page reached upstream: %v", up.calls)
	}
	// refresh spends again.
	if _, err := e.SearchServices(context.Background(), q, true); err != nil || *up.credits != 48 {
		t.Errorf("refresh: %v, credits %d", err, *up.credits)
	}
}

// A failed search does not hide what it spent.
func TestAFailedSearchReportsWhatItSpent(t *testing.T) {
	up := creditFake(50, 1)
	up.searchErr = &shodan.Error{Code: shodan.CodeUpstream, Status: 500, Message: "upstream answered 500"}
	_, err := searchEngine(t, up, 0).SearchServices(context.Background(), SearchQuery{Query: "port:443"}, false)
	if Code(err) != shodan.CodeUpstream || !strings.Contains(err.Error(), "1 credit(s) were spent") {
		t.Errorf("err: %v", err)
	}
}

func TestSearchRefusesBeforeSpending(t *testing.T) {
	up := creditFake(50, 1)
	e := searchEngine(t, up, 0)
	for _, tc := range []struct {
		q    SearchQuery
		code string
	}{
		{SearchQuery{Query: "port:443", Page: MaxSearchPage + 1}, CodeInvalidArgument},
		{SearchQuery{Query: "port:443", Page: -1}, CodeInvalidArgument},
		{SearchQuery{Query: "net:10.0.0.0/8"}, CodeInvalidArgument},
		{SearchQuery{Query: "nosuchfilter:x"}, CodeInvalidArgument},
		{SearchQuery{Query: "vuln:CVE-2000-0001"}, CodePlanRestricted},
		{SearchQuery{Query: "port:443", Facets: []FacetSpec{{Name: "vuln", N: 3}}}, CodePlanRestricted},
	} {
		_, err := e.SearchServices(context.Background(), tc.q, false)
		wantCode(t, err, tc.code)
	}
	if up.count("tokens")+up.count("search")+up.count("apiinfo") != 0 {
		t.Errorf("a refused query reached the credit path: %v", up.calls)
	}
}

func TestParseQueryPredicts(t *testing.T) {
	up := creditFake(50, 1)
	e := searchEngine(t, up, 0)
	r, err := e.ParseQuery(context.Background(), "port:443 apache")
	if err != nil || r.PredictedCost != 1 || len(r.Filters) != 1 {
		t.Errorf("filtered: %+v %v", r, err)
	}
	r, err = e.ParseQuery(context.Background(), "apache")
	if err != nil || r.PredictedCost != 0 {
		t.Errorf("free text: %+v %v", r, err)
	}
	_, err = e.ParseQuery(context.Background(), "ip:192.168.1.1")
	wantCode(t, err, CodeInvalidArgument)
	if up.count("search") != 0 || *up.credits != 50 {
		t.Error("parse_query spent")
	}
}

// From the pre-release verification (M2, L1).

// A failed search that was not charged is not a mismatch: the process keeps
// searching, and the advice to retry a 429 holds.
func TestAFreeFailureDoesNotStopSearching(t *testing.T) {
	up := creditFake(50, 0)
	up.searchErr = &shodan.Error{Code: shodan.CodeRateLimited, Status: 429, Message: "429"}
	e := searchEngine(t, up, 0)
	_, err := e.SearchServices(context.Background(), SearchQuery{Query: "port:443"}, false)
	wantCode(t, err, shodan.CodeRateLimited)
	up.searchErr, up.charge = nil, 1
	if _, err := e.SearchServices(context.Background(), SearchQuery{Query: "port:443"}, false); err != nil {
		t.Errorf("searching stopped after a free failure: %v", err)
	}
}

// A 401 on the search, with /api-info answering before and after, is the plan
// or the credits — not the key.
func TestASearch401WithAWorkingKeyIsNotTheKey(t *testing.T) {
	up := creditFake(50, 0)
	up.searchErr = &shodan.Error{Code: shodan.CodeAuthFailed, Status: 401, Message: "401"}
	_, err := searchEngine(t, up, 0).SearchServices(context.Background(), SearchQuery{Query: "port:443"}, false)
	wantCode(t, err, CodePlanRestricted)
	if strings.Contains(err.Error(), "check [api] key") {
		t.Errorf("the key is blamed: %v", err)
	}
}

// A page that cannot be projected is not cached after it was paid for, and the
// error says what was spent.
func TestAnUnprojectablePageIsNotCachedAndSaysWhatItCost(t *testing.T) {
	up := creditFake(50, 1)
	up.searchBody = `{"total": 1, "matches": [{"ip_str": "1.2.3.4", "port": "443"}]}`
	e := searchEngine(t, up, 0)
	_, err := e.SearchServices(context.Background(), SearchQuery{Query: "port:443"}, false)
	if Code(err) != shodan.CodeDecode || !strings.Contains(err.Error(), "1 credit(s) were spent") {
		t.Errorf("err: %v", err)
	}
	_, _ = e.SearchServices(context.Background(), SearchQuery{Query: "port:443"}, false)
	if up.count("search") != 2 {
		t.Errorf("an unprojectable page was cached (searches %d)", up.count("search"))
	}
}

// A paid-for page whose scalars arrive as numbers reads like any other.
func TestASearchMatchWithNumericScalarsReads(t *testing.T) {
	up := creditFake(50, 1)
	up.searchBody = `{"total": 1, "matches": [{"ip_str": "1.2.3.4", "port": 443, "transport": "tcp",
	  "org": 64500, "location": {"country_code": 392}, "product": "ExampleServer", "version": 2}]}`
	s, err := searchEngine(t, up, 0).SearchServices(context.Background(), SearchQuery{Query: "port:443"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if r := s.Rows[0]; r.Org != "64500" || r.CountryCode != "392" || r.Version != "2" {
		t.Errorf("row: %+v", r)
	}
}
