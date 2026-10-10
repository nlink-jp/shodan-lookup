package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/ipaddr"
	"github.com/nlink-jp/shodan-lookup/internal/shodan"
)

// MaxSearchPage bounds search_services' page. One call was measured to cost at
// most one credit (pages 1 and 2); pages past 2 are unmeasured, and 10 is
// conservative against the Membership website's 20 pages.
const MaxSearchPage = 10

// QueryReading is how Shodan reads a query (tokens), with what a search for it
// would cost. Credit-free.
type QueryReading struct {
	Query         string          `json:"query"`
	Filters       []string        `json:"filters"`
	Attributes    json.RawMessage `json:"attributes,omitempty"`
	Errors        []string        `json:"errors,omitempty"`
	FreeText      string          `json:"free_text"`
	PredictedCost int             `json:"predicted_credits_page_1"`
	Notes         []string        `json:"notes,omitempty"`
}

// ParseQuery checks a query as a search would — gate, filter and facet
// names, plan restrictions — and asks Shodan how it reads it. Nothing is
// spent.
func (e *Engine) ParseQuery(ctx context.Context, query string) (*QueryReading, error) {
	terms, err := ipaddr.CheckQuery(query)
	if err != nil {
		return nil, err
	}
	if err := e.checkKey(); err != nil {
		return nil, err
	}
	if err := e.checkNames(ctx, terms, nil, false); err != nil {
		return nil, err
	}
	t, err := e.tokens(ctx, query)
	if err != nil {
		return nil, err
	}
	r := &QueryReading{Query: query, Filters: t.Filters, Attributes: t.Attributes, Errors: t.Errors, FreeText: t.String,
		PredictedCost: predictCost(t, 1)}
	r.Notes = append(r.Notes, "the prediction is Shodan's own reading: 1 credit when the query uses a filter or asks for page 2 or later, else 0 (measured on three searches)")
	return r, nil
}

type tokensBody struct {
	Filters    []string        `json:"filters"`
	Attributes json.RawMessage `json:"attributes"`
	Errors     []string        `json:"errors"`
	String     string          `json:"string"`
}

func (e *Engine) tokens(ctx context.Context, query string) (*tokensBody, error) {
	resp, err := e.up.Tokens(ctx, query)
	if err != nil {
		return nil, err
	}
	var t tokensBody
	if json.Unmarshal(resp.Body, &t) != nil || t.Filters == nil {
		return nil, &shodan.Error{Code: shodan.CodeDecode, Message: "Shodan's reading of the query (tokens) has no filters list"}
	}
	return &t, nil
}

func predictCost(t *tokensBody, page int) int {
	if len(t.Filters) > 0 || page > 1 {
		return 1
	}
	return 0
}

// SearchQuery is one page of a search.
type SearchQuery struct {
	Query  string
	Facets []FacetSpec
	Page   int // 1..MaxSearchPage; 0 means 1
}

// Search is one page of services matching a query. Rows are a compact
// projection of each banner — a page measured up to 9.3 MB — and the banner
// itself is lookup_host's or get_service's to show.
type Search struct {
	Query      string     `json:"query"`
	Page       int        `json:"page"`
	Unit       string     `json:"unit"`
	Total      int        `json:"total"`
	Rows       []Row      `json:"rows"`
	Facets     []Facet    `json:"facets,omitempty"`
	Credits    *Credits   `json:"credits,omitempty"`
	Provenance Provenance `json:"provenance"`
	Notes      []string   `json:"notes,omitempty"`

	body json.RawMessage
}

// Raw is the upstream page this answer was projected from — every banner in
// full — for the CLI's search --raw. The credits were spent for it.
func (s *Search) Raw() json.RawMessage { return s.body }

// Row is one matching service.
type Row struct {
	IP          string   `json:"ip"`
	Port        int      `json:"port"`
	Transport   string   `json:"transport"`
	Module      string   `json:"module,omitempty"`
	Org         string   `json:"org,omitempty"`
	CountryCode string   `json:"country_code,omitempty"`
	Hostnames   []string `json:"hostnames,omitempty"`
	Product     string   `json:"product,omitempty"`
	Version     string   `json:"version,omitempty"`
	Title       string   `json:"title,omitempty"`
	Timestamp   string   `json:"timestamp,omitempty"`
	VulnCount   int      `json:"vuln_count"`
}

// Credits is what a search spent, read from /api-info before and after it.
type Credits struct {
	Predicted int  `json:"predicted"`
	Before    int  `json:"before"`
	After     *int `json:"after,omitempty"` // absent when the read after the search failed
	Spent     *int `json:"spent,omitempty"`
	Floor     int  `json:"floor"`
}

type wireMatch struct {
	wireService
	IPStr     string   `json:"ip_str"`
	Org       *text    `json:"org"`
	Hostnames []string `json:"hostnames"`
	Location  struct {
		CountryCode *text `json:"country_code"`
	} `json:"location"`
}

// SearchServices returns one page of a search. It is the only path that
// spends query credits, and it is guarded here rather than by any argument:
//
//  1. a cached page is served without sending anything;
//  2. once a search in this process spent other than predicted, or its
//     spending could not be read, every later uncached search is refused;
//  3. Shodan's own reading of the query (tokens, free) gives the prediction;
//  4. the remainder is read and the search refused if, counting it as one
//     credit whatever the prediction, it would cross the floor;
//  5. the remainder is read again afterwards and compared with the prediction.
//
// Any failure in steps 3–4 sends nothing (fail-closed).
func (e *Engine) SearchServices(ctx context.Context, q SearchQuery, refresh bool) (*Search, error) {
	if q.Page == 0 {
		q.Page = 1
	}
	if q.Page < 1 || q.Page > MaxSearchPage {
		return nil, invalid(fmt.Sprintf("page must be between 1 and %d", MaxSearchPage))
	}
	terms, err := ipaddr.CheckQuery(q.Query)
	if err != nil {
		return nil, err
	}
	if err := e.checkKey(); err != nil {
		return nil, err
	}
	if err := e.checkNames(ctx, terms, q.Facets, refresh); err != nil {
		return nil, err
	}
	specs := make([]string, 0, len(q.Facets))
	for _, f := range q.Facets {
		specs = append(specs, f.Name+":"+strconv.Itoa(f.N))
	}
	facetParam := strings.Join(specs, ",")
	key := cache.Key("search", q.Query, facetParam, strconv.Itoa(q.Page))

	// 1. A cached page costs nothing and checks nothing.
	if !refresh && e.cfg.SearchTTL > 0 {
		if raw, ok := e.cache.Get(key, e.now(), e.cfg.SearchTTL); ok {
			var en entry
			if json.Unmarshal(raw, &en) == nil && validSearch(en.Body) == nil {
				s, err := projectSearch(&en, true, q)
				if err == nil {
					s.Notes = append(s.Notes, "from the local cache: no credit was spent (refresh would spend again)")
				}
				return s, err
			}
		}
	}

	// 2. A process whose spending did not match stops searching.
	e.mu.Lock()
	halt := e.searchHalt
	e.mu.Unlock()
	if halt != "" {
		return nil, &Error{Code: CodeCreditMismatch, Message: "searching is stopped for this process: " + halt + ". Restart it after checking get_quota"}
	}

	// 3. Shodan's reading gives the prediction.
	t, err := e.tokens(ctx, q.Query)
	if err != nil {
		return nil, err
	}
	predicted := predictCost(t, q.Page)

	// 4. The floor, counting this search as one credit.
	before, err := e.remaining(ctx)
	if err != nil {
		return nil, err
	}
	floor := e.cfg.CreditFloor
	if before-1 < floor {
		return nil, &Error{Code: CodeCreditFloor, Message: fmt.Sprintf(
			"%d query credit(s) remain and the floor is %d; a search is counted as one credit, so it is not sent (credits renew at the start of the month; the operator sets [search] credit_floor)", before, floor)}
	}

	en, _, serr := e.fetch(ctx, key, e.cfg.SearchTTL, true,
		func(ctx context.Context) (*shodan.Response, error) {
			return e.up.Search(ctx, q.Query, facetParam, q.Page)
		}, validSearch)

	// 5. What it actually spent.
	credits := &Credits{Predicted: predicted, Before: before, Floor: floor}
	after, aerr := e.remaining(ctx)
	switch {
	case aerr != nil:
		e.halt("the credits spent by a search could not be read afterwards (" + Code(aerr) + ")")
	default:
		spent := before - after
		credits.After, credits.Spent = &after, &spent
		// A search that failed and was not charged spent what a failure
		// should; only a charge that differs from the prediction — or any
		// charge for a failure beyond the prediction — means the guard's
		// model is wrong.
		failedFree := serr != nil && spent == 0
		if spent != predicted && !failedFree {
			e.halt(fmt.Sprintf("a search predicted to spend %d credit(s) spent %d (%d → %d); another process using the key would do this too", predicted, spent, before, after))
		}
	}
	if serr != nil {
		serr = searchError(serr, aerr == nil)
		if credits.Spent != nil && *credits.Spent > 0 {
			return nil, fmt.Errorf("%w (and %d credit(s) were spent — retrying would spend again)", serr, *credits.Spent)
		}
		return nil, serr
	}
	s, err := projectSearch(en, false, q)
	if err != nil {
		if credits.Spent != nil && *credits.Spent > 0 {
			return nil, fmt.Errorf("%w (and %d credit(s) were spent)", err, *credits.Spent)
		}
		return nil, err
	}
	s.Credits = credits
	e.mu.Lock()
	if e.searchHalt != "" {
		s.Notes = append(s.Notes, "searching is now stopped for this process: "+e.searchHalt)
	}
	e.mu.Unlock()
	return s, nil
}

// searchError reads a failed search. A 401 there, when /api-info answered
// with the same key before and after, is not the key: it is the plan or the
// remaining credits refusing the search.
func searchError(err error, keyWorked bool) error {
	if keyWorked && shodan.Code(err) == shodan.CodeAuthFailed {
		return &Error{Code: CodePlanRestricted, Message: "Shodan refused the search (401) although the key works for /api-info — the plan or the remaining query credits do not allow it; check get_quota"}
	}
	return err
}

func (e *Engine) halt(why string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.searchHalt == "" {
		e.searchHalt = why
	}
}

// remaining reads query_credits, live.
func (e *Engine) remaining(ctx context.Context) (int, error) {
	q, err := e.GetQuota(ctx)
	if err != nil {
		return 0, err
	}
	return q.QueryCredits, nil
}

// validSearch accepts a body with a total and a list of matches. A value of
// an unexpected type inside a match is the projection's to leave out
// (decodeLoose): a page that was paid for is not lost over one field.
func validSearch(body []byte) error {
	var w searchWire
	if _, err := decodeLoose(body, &w); err != nil {
		return &shodan.Error{Code: shodan.CodeDecode, Message: "Shodan's search answer is " + err.Error()}
	}
	if w.Total == nil || w.Matches == nil {
		return &shodan.Error{Code: shodan.CodeDecode, Message: "Shodan's search answer has no total or no matches"}
	}
	return nil
}

type searchWire struct {
	Total   *int        `json:"total"`
	Matches []wireMatch `json:"matches"`
	Facets  map[string][]struct {
		Count int             `json:"count"`
		Value json.RawMessage `json:"value"`
	} `json:"facets"`
}

func projectSearch(en *entry, cached bool, q SearchQuery) (*Search, error) {
	var w searchWire
	sk, err := decodeLoose(en.Body, &w)
	if err != nil || w.Total == nil {
		return nil, &shodan.Error{Code: shodan.CodeDecode, Message: "Shodan's search answer is not the shape this tool reads"}
	}
	s := &Search{Query: q.Query, Page: q.Page, Unit: "services", Total: *w.Total, Rows: []Row{}, Provenance: provenance(en, cached), body: en.Body}
	s.Provenance.DocID = docID(en.Body)
	for _, m := range w.Matches {
		r := Row{IP: m.IPStr, Port: m.Port, Transport: m.Transport, Module: m.Shodan.Module, Org: str(m.Org),
			CountryCode: str(m.Location.CountryCode), Hostnames: m.Hostnames, Product: str(m.Product),
			Version: str(m.Version), Title: httpTitle(m.wireService), VulnCount: len(m.Vulns)}
		if t, ok := shodanTime(m.Timestamp); ok {
			r.Timestamp = t.Format(time.RFC3339)
		}
		s.Rows = append(s.Rows, r)
	}
	for _, f := range q.Facets {
		out := Facet{Name: f.Name, Requested: f.N, Values: []FacetValue{}}
		for _, v := range w.Facets[f.Name] {
			out.Values = append(out.Values, FacetValue{Value: facetValue(v.Value), Count: v.Count})
		}
		s.Facets = append(s.Facets, out)
	}
	if n := sk.note("the CLI's search --raw"); n != "" {
		s.Notes = append(s.Notes, n)
	}
	s.Notes = append(s.Notes,
		"the unit is services (banners), not hosts; a page holds at most 100",
		"Shodan's index is live: total and the rows can shift between pages")
	return s, nil
}
