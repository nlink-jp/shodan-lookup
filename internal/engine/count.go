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

// MaxFacetValues is the most values one facet may ask for. 1,000 was measured
// (39 KB for ip:1000); nothing above it was.
const MaxFacetValues = 1000

// DefaultFacetValues is what a facet without :N asks for.
const DefaultFacetValues = 10

// isRestricted reports the filters and facets Shodan withholds from
// Membership (pricing page: vuln and tag), with the names derived from them
// that its lists carry (has_vuln, vuln.verified). They are refused before
// sending because the restriction does not come back as an error:
// vuln:CVE-2021-44228 answered 200 with a count of 3.
func isRestricted(name string) bool {
	switch {
	case name == "vuln", name == "tag", name == "has_vuln":
		return true
	case strings.HasPrefix(name, "vuln."), strings.HasPrefix(name, "tag."):
		return true
	}
	return false
}

// listTTL is how long the filter and facet name lists stay cached. They are
// vocabulary, not data, and change with Shodan releases.
const listTTL = 24 * time.Hour

// FacetSpec is one requested breakdown.
type FacetSpec struct {
	Name string
	N    int
}

// ParseFacet reads "name" or "name:N".
func ParseFacet(s string) (FacetSpec, error) {
	name, n, hasN := strings.Cut(strings.TrimSpace(s), ":")
	f := FacetSpec{Name: name, N: DefaultFacetValues}
	if name == "" {
		return f, invalid(fmt.Sprintf("facet %q has no name", s))
	}
	if hasN {
		v, err := strconv.Atoi(n)
		if err != nil || v < 1 || v > MaxFacetValues {
			return f, invalid(fmt.Sprintf("facet %q: the count after ':' must be an integer from 1 to %d", s, MaxFacetValues))
		}
		f.N = v
	}
	return f, nil
}

// Count is the answer to "how many services match this query". The unit is
// services (banners), not hosts: an IP with two matching services counts
// twice, and its ip facet value is 2.
type Count struct {
	Query      string     `json:"query"`
	Unit       string     `json:"unit"`
	Total      int        `json:"total"`
	Facets     []Facet    `json:"facets,omitempty"`
	Provenance Provenance `json:"provenance"`
	Notes      []string   `json:"notes,omitempty"`
}

// Facet is one breakdown: the top values, each with its count of services.
type Facet struct {
	Name      string       `json:"name"`
	Requested int          `json:"requested"`
	Values    []FacetValue `json:"values"`
}

// FacetValue is one value of a breakdown.
type FacetValue struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// CountServices counts the services matching query, with facet breakdowns.
// Credit-free (measured). The query is gated (internal addresses, quotes,
// length), every filter and facet name is checked against upstream's own
// lists, and the plan-restricted ones are refused — all before it is sent.
func (e *Engine) CountServices(ctx context.Context, query string, facets []FacetSpec, refresh bool) (*Count, error) {
	terms, err := ipaddr.CheckQuery(query)
	if err != nil {
		return nil, err
	}
	if err := e.checkKey(); err != nil {
		return nil, err
	}
	if err := e.checkNames(ctx, terms, facets, refresh); err != nil {
		return nil, err
	}

	specs := make([]string, 0, len(facets))
	for _, f := range facets {
		specs = append(specs, f.Name+":"+strconv.Itoa(f.N))
	}
	facetParam := strings.Join(specs, ",")
	en, cached, err := e.fetch(ctx, cache.Key("count", query, facetParam), e.cfg.CountTTL, refresh,
		func(ctx context.Context) (*shodan.Response, error) { return e.up.Count(ctx, query, facetParam) }, validCount)
	if err != nil {
		return nil, err
	}

	var w struct {
		Total  *int `json:"total"`
		Facets map[string][]struct {
			Count int             `json:"count"`
			Value json.RawMessage `json:"value"`
		} `json:"facets"`
	}
	if json.Unmarshal(en.Body, &w) != nil || w.Total == nil {
		return nil, &shodan.Error{Code: shodan.CodeDecode, Message: "Shodan's count for the query has no total"}
	}
	c := &Count{Query: query, Unit: "services", Total: *w.Total, Provenance: provenance(en, cached)}
	for _, f := range facets {
		out := Facet{Name: f.Name, Requested: f.N, Values: []FacetValue{}}
		for _, v := range w.Facets[f.Name] {
			out.Values = append(out.Values, FacetValue{Value: facetValue(v.Value), Count: v.Count})
		}
		if _, ok := w.Facets[f.Name]; !ok {
			c.Notes = append(c.Notes, fmt.Sprintf("Shodan returned no %s breakdown", f.Name))
		}
		c.Facets = append(c.Facets, out)
	}
	c.Notes = append(c.Notes, "the unit is services (banners), not hosts: an IP with two matching services counts twice")
	if len(facets) > 0 {
		c.Notes = append(c.Notes, "each breakdown lists only its top values, as many as requested; the number of distinct values beyond them is not reported")
	}
	if c.Total == 0 {
		c.Notes = append(c.Notes, "0 matching services: every filter name was checked against Shodan's list, so this is Shodan's answer to the query as written")
	}
	return c, nil
}

// checkNames holds every filter and facet name to the lists Shodan publishes.
// An unknown filter becomes free text upstream and matches nothing; an unknown
// facet is dropped without a word (both measured). Either would read as
// "nothing found".
func (e *Engine) checkNames(ctx context.Context, terms []ipaddr.Term, facets []FacetSpec, refresh bool) error {
	var filterNames []string
	for _, t := range terms {
		if t.Filter == "" {
			continue
		}
		if isRestricted(t.Filter) {
			return planRestricted("filter", t.Filter)
		}
		filterNames = append(filterNames, t.Filter)
		if err := checkValue(t); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, f := range facets {
		if isRestricted(f.Name) {
			return planRestricted("facet", f.Name)
		}
		if seen[f.Name] {
			return invalid(fmt.Sprintf("facet %q is asked for twice", f.Name))
		}
		seen[f.Name] = true
	}
	if len(filterNames) > 0 {
		if n, err := e.unknownName(ctx, "filters", e.up.Filters, filterNames, refresh); err != nil {
			return err
		} else if n != "" {
			return invalid(fmt.Sprintf("%q is not a Shodan filter name (filter names are lower case; to search for the text, quote it). Shodan would read it as free text and match nothing", n+":"))
		}
	}
	if len(facets) > 0 {
		names := make([]string, 0, len(facets))
		for _, f := range facets {
			names = append(names, f.Name)
		}
		if n, err := e.unknownName(ctx, "facets", e.up.Facets, names, refresh); err != nil {
			return err
		} else if n != "" {
			return invalid(fmt.Sprintf("%q is not a Shodan facet name. Shodan would drop it without saying so", n))
		}
	}
	return nil
}

// unknownName returns the first name not on Shodan's list, or "". A list
// read from the cache is fetched again once before a name is refused, so a
// name Shodan added since does not wait out the list's TTL.
func (e *Engine) unknownName(ctx context.Context, kind string, get func(context.Context) (*shodan.Response, error), names []string, refresh bool) (string, error) {
	known, cached, err := e.nameList(ctx, kind, get, refresh)
	if err != nil {
		return "", err
	}
	for _, n := range names {
		if known[n] {
			continue
		}
		if cached {
			if known, _, err = e.nameList(ctx, kind, get, true); err != nil {
				return "", err
			}
			cached = false
			if known[n] {
				continue
			}
		}
		return n, nil
	}
	return "", nil
}

// checkValue refuses filter values that were measured to match nothing
// without an error.
func checkValue(t ipaddr.Term) error {
	if t.Filter != "ssl.cert.fingerprint" {
		return nil
	}
	for v := range strings.SplitSeq(t.Value, ",") {
		// Written as tools print it: AB:CD:… (OpenSSL, browsers), spaced, any case.
		v = strings.NewReplacer(":", "", " ", "").Replace(v)
		if len(v) == 64 && isHex(v) {
			return invalid("ssl.cert.fingerprint matches a certificate's SHA-1 (40 hex digits); a SHA-256 matches nothing, without an error (measured). Use the sha1 that lookup_host reports")
		}
	}
	return nil
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func planRestricted(kind, name string) error {
	return &Error{Code: CodePlanRestricted, Message: fmt.Sprintf(
		"the %s %q is not available on a Membership plan (Shodan's pricing page); it is refused because the restriction does not come back as an error — a vuln: count measured 3 for Log4Shell", kind, name)}
}

// nameList reads one of Shodan's name lists through the cache. A body that
// is not a non-empty list of names is an error and is never cached.
func (e *Engine) nameList(ctx context.Context, kind string, get func(context.Context) (*shodan.Response, error), refresh bool) (map[string]bool, bool, error) {
	parse := func(body []byte) ([]string, error) {
		var names []string
		if json.Unmarshal(body, &names) != nil || len(names) == 0 {
			return nil, &shodan.Error{Code: shodan.CodeDecode, Message: "Shodan's list of " + kind + " is not a list of names"}
		}
		return names, nil
	}
	en, cached, err := e.fetch(ctx, cache.Key("names", kind), listTTL, refresh, get,
		func(b []byte) error { _, err := parse(b); return err })
	if err != nil {
		return nil, false, err
	}
	names, err := parse(en.Body)
	if err != nil {
		return nil, false, err
	}
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return set, cached, nil
}

// validCount accepts a count body that carries a total.
func validCount(body []byte) error {
	var c struct {
		Total *int `json:"total"`
	}
	if json.Unmarshal(body, &c) != nil || c.Total == nil {
		return &shodan.Error{Code: shodan.CodeDecode, Message: "Shodan's count has no total"}
	}
	return nil
}

// facetValue renders a facet value, which Shodan sends as a string or a
// number depending on the facet (port values are numbers).
func facetValue(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

// Quota is the plan and remaining credits of the key. Never cached: it is the
// account's state now, and a remembered one would answer from the past.
type Quota struct {
	Plan         string `json:"plan"`
	PlanName     string `json:"plan_name,omitempty"`
	QueryCredits int    `json:"query_credits"`
	ScanCredits  int    `json:"scan_credits"`
	MonitoredIPs int    `json:"monitored_ips"`
	Limits       struct {
		QueryCredits int `json:"query_credits"`
		ScanCredits  int `json:"scan_credits"`
		MonitoredIPs int `json:"monitored_ips"`
	} `json:"usage_limits"`
	FetchedAt string   `json:"fetched_at"`
	Notes     []string `json:"notes,omitempty"`
}

// planNames maps the plan identifiers that were observed to the product name.
// Only measured ones: an identifier not here is passed on as it came.
var planNames = map[string]string{"dev": "Membership"}

// GetQuota reads the plan and remaining credits, always live.
func (e *Engine) GetQuota(ctx context.Context) (*Quota, error) {
	if err := e.checkKey(); err != nil {
		return nil, err
	}
	resp, err := e.up.APIInfo(ctx)
	if err != nil {
		return nil, err
	}
	var w struct {
		Plan         *string `json:"plan"`
		QueryCredits *int    `json:"query_credits"`
		ScanCredits  *int    `json:"scan_credits"`
		MonitoredIPs *int    `json:"monitored_ips"`
		UsageLimits  struct {
			QueryCredits int `json:"query_credits"`
			ScanCredits  int `json:"scan_credits"`
			MonitoredIPs int `json:"monitored_ips"`
		} `json:"usage_limits"`
	}
	if json.Unmarshal(resp.Body, &w) != nil || w.Plan == nil || w.QueryCredits == nil {
		return nil, &shodan.Error{Code: shodan.CodeDecode, Message: "Shodan's /api-info answer has no plan or query_credits"}
	}
	q := &Quota{Plan: *w.Plan, PlanName: planNames[*w.Plan], QueryCredits: *w.QueryCredits,
		FetchedAt: resp.FetchedAt.UTC().Format(time.RFC3339)}
	if w.ScanCredits != nil {
		q.ScanCredits = *w.ScanCredits
	}
	if w.MonitoredIPs != nil {
		q.MonitoredIPs = *w.MonitoredIPs
	}
	q.Limits.QueryCredits, q.Limits.ScanCredits, q.Limits.MonitoredIPs = w.UsageLimits.QueryCredits, w.UsageLimits.ScanCredits, w.UsageLimits.MonitoredIPs
	q.Notes = append(q.Notes, "credits renew at the start of each month; host lookups and counts spend none (measured)")
	return q, nil
}
