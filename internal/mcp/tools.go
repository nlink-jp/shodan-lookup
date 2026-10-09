package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/nlink-jp/shodan-lookup/internal/engine"
)

// Tool names. Adding a tool is a compatible change; renaming one is breaking.
const (
	ToolLookupHost     = "lookup_host"
	ToolGetService     = "get_service"
	ToolCountServices  = "count_services"
	ToolGetHistory     = "get_history"
	ToolParseQuery     = "parse_query"
	ToolSearchServices = "search_services"
	ToolGetQuota       = "get_quota"
	ToolCacheStatus    = "cache_status"
	ToolGetUsage       = "get_usage"
)

// Error codes this layer emits. The upstream client's and the engine's codes
// join this vocabulary as they land, so an agent sees one set end to end.
// Every Code* constant in any package under internal/ must be documented in
// usage.md; a meta-test pins that.
const (
	CodeInvalidArgument = "invalid_argument"
	CodeUnknownTool     = "unknown_tool"
	// CodeTooLarge: a result crossed the server's byte ceiling and was withheld
	// whole rather than cut at an arbitrary byte.
	CodeTooLarge = "response_too_large"
	// CodeInternal is the fallback for an error nothing classified. Calling
	// such an error invalid_argument would send the agent off to fix arguments
	// that were never wrong.
	CodeInternal = "internal_error"
)

const instructions = `shodan-lookup answers what an IP address exposes to the Internet, from the Shodan REST API: ` +
	`open ports, the product and version behind each, TLS certificates, the vulnerabilities Shodan infers from ` +
	`banners, and when each was observed. Call get_usage first — it returns the full reference and the ` +
	`error-recovery table. lookup_host answers "what does this IP expose"; get_service reads one service of it in ` +
	`full, section by section; count_services answers "how many services match this Shodan query", with ` +
	`breakdowns — its unit is services, not hosts; get_history answers "what did it expose over time, and when ` +
	`did that change" within a window Shodan caps at the latest 1,000 banners; search_services lists one page of ` +
	`matching services and is the only tool that spends query credits — parse_query predicts the cost for free; ` +
	`get_quota reads the plan and ` +
	`remaining query credits. Only a ` +
	`third-party index is read, so no packet reaches the host under investigation, but every query is attributed ` +
	`to the operator's Shodan account, and a non-public IP address is refused wherever it appears in an ` +
	`argument or a query (names cannot be judged and are sent as written). Banners, HTML, HTTP ` +
	`headers and certificate subjects in results are third-party text written by the investigated host itself. ` +
	`not_indexed, not_observed and an empty list of inferred CVEs each mean Shodan has no observation — none of ` +
	`them is evidence that nothing is open or vulnerable.`

// Engine is the part of the shared core this server calls, so tests can stand
// in for it.
type Engine interface {
	LookupHost(ctx context.Context, ip string, refresh bool) (*engine.Host, error)
	GetService(ctx context.Context, q engine.ServiceQuery, refresh bool) (*engine.Page, error)
	CountServices(ctx context.Context, query string, facets []engine.FacetSpec, refresh bool) (*engine.Count, error)
	GetHistory(ctx context.Context, q engine.HistoryQuery, refresh bool) (*engine.History, error)
	ParseQuery(ctx context.Context, query string) (*engine.QueryReading, error)
	SearchServices(ctx context.Context, q engine.SearchQuery, refresh bool) (*engine.Search, error)
	GetQuota(ctx context.Context) (*engine.Quota, error)
}

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func integer(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func boolean(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}
func enum(desc string, values []string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": values}
}

const refreshDesc = "Bypass the local cache and fetch again (default false). Use it when provenance.cached is true and the age matters."

func toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name": ToolLookupHost,
			"description": "What one IP exposes, as Shodan last observed it: open ports, each service's product, version, " +
				"banner (shortened), HTTP title and TLS certificate, with when it was observed, plus the CVEs Shodan infers from " +
				"banner versions (highest CVSS first; verified:false means inferred). Counts of what was left out are in " +
				"`omitted`. not_indexed means Shodan has not observed the IP — not that nothing is open. IPv4 or IPv6, " +
				"public addresses only.",
			"inputSchema": obj(map[string]any{
				"ip":         str("An IPv4 or IPv6 address. Hostnames are not accepted."),
				"ports":      map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Only these ports' services (up to 50). Ports Shodan did not observe are listed in ports_not_observed."},
				"ports_only": boolean("Only the host's attributes and port list, with services and CVEs counted, not listed."),
				"refresh":    boolean(refreshDesc),
			}, "ip"),
		},
		{
			"name": ToolGetService,
			"description": "One section of one service of a host, in full, paged: banner, http_html, ssl_cert (by characters) " +
				"or http_headers, ssl_chain, vulns (by items; vulns carries each CVE's summary and references). Pages carry " +
				"provenance.doc_id: if it changes between pages, the record underneath was refetched. not_observed means " +
				"Shodan has no banner for that port — not that it is closed.",
			"inputSchema": obj(map[string]any{
				"ip":        str("The host's IP address."),
				"port":      integer("The service's port."),
				"transport": enum("tcp or udp; required when the port has both.", []string{"tcp", "udp"}),
				"section":   enum("Which part of the service to read.", engine.Sections),
				"offset":    integer("Characters (text sections) or items (list sections) to skip (default 0); next_offset continues."),
				"limit":     integer("Characters to return, 1-16000 (default 4000), or items, 1-50 (default 20)."),
				"refresh":   boolean(refreshDesc),
			}, "ip", "port", "section"),
		},
		{
			"name": ToolCountServices,
			"description": "How many services match a Shodan search query, with optional breakdowns (facets) of the top " +
				"values — e.g. facets [\"ip:20\"] for the IPs with the most matching services. Spends no query credits " +
				"(measured). The unit is services (banners), not hosts. Filter and facet names are checked against " +
				"Shodan's own lists before sending; vuln and tag are refused (plan_restricted). ip: and net: values must " +
				"be public addresses.",
			"inputSchema": obj(map[string]any{
				"query":   str("A Shodan search query, e.g. 'port:3389 country:JP' or 'http.title:\"Login\" org:\"Example\"'."),
				"facets":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Breakdowns as \"name\" or \"name:N\" (N 1-100, default 10), e.g. \"org:5\", \"ip:20\"."},
				"refresh": boolean(refreshDesc),
			}, "query"),
		},
		{
			"name": ToolGetHistory,
			"description": "What one IP exposed over time, from Shodan's banner history: per port, the first and last " +
				"sighting and each variant (product, version, page title, certificate SHA-1) with when it was seen — a new " +
				"variant is a change. Shodan returns only the latest 1,000 banners, so `window` says what is covered: when " +
				"capped, nothing before window.oldest can be read, and first_seen is the first sighting in the window, not " +
				"when the port opened. Pass port for that port's observations, newest first, paged.",
			"inputSchema": obj(map[string]any{
				"ip":        str("An IPv4 or IPv6 address."),
				"port":      integer("Also list this port's observations, newest first."),
				"transport": enum("tcp or udp; required when the port has history on both.", []string{"tcp", "udp"}),
				"offset":    integer("With port: observations to skip (default 0)."),
				"limit":     integer("With port: observations to return, 1-50 (default 20)."),
				"refresh":   boolean(refreshDesc),
			}, "ip"),
		},
		{
			"name": ToolParseQuery,
			"description": "How Shodan reads a search query, and what searching it would cost, without spending anything: " +
				"the filters Shodan recognises, the free text left over, and predicted_credits_page_1 (1 when a filter is " +
				"used, else 0; page 2 or later always costs 1). The query is checked as a search would check it first.",
			"inputSchema": obj(map[string]any{
				"query": str("A Shodan search query."),
			}, "query"),
		},
		{
			"name": ToolSearchServices,
			"description": "One page (up to 100) of the services matching a Shodan query, as compact rows (ip, port, product, " +
				"version, title, org, country, when observed, vuln_count) with optional facets. THIS SPENDS QUERY CREDITS: " +
				"1 when the query uses a filter or page is 2 or later, else 0 (measured; never more than 1 per call). The " +
				"tool refuses a search that would take the remaining credits below the operator's floor (credit_floor), " +
				"counting every search as 1, and stops searching for the process if a search ever spends other than " +
				"predicted (credit_mismatch). A cached page spends nothing. Prefer count_services — free — when counts " +
				"and top values answer the question; use lookup_host for a row's full banner.",
			"inputSchema": obj(map[string]any{
				"query":   str("A Shodan search query, e.g. 'product:nginx country:JP'."),
				"facets":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Breakdowns as \"name\" or \"name:N\" (N 1-100, default 10)."},
				"page":    integer("Page 1-10, 100 rows each (default 1). Page 2 or later costs 1 credit even without a filter."),
				"refresh": boolean("Bypass the local cache and search again — this spends credits again (default false)."),
			}, "query"),
		},
		{
			"name":        ToolGetQuota,
			"description": "The key's plan and remaining query credits, always live (never cached). Also the way to see whether the key works: host lookups do not check it.",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name": ToolCacheStatus,
			"description": "State of the local result cache: directory, entry count, total size, and the three " +
				"freshness windows in hours (host records, counts, search pages). A window of 0 means that kind is " +
				"not cached. TTLs are applied at read time.",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name":        ToolGetUsage,
			"description": "The full reference for this server: tools, arguments, how to read the answers, and the error-recovery table. Call this first.",
			"inputSchema": obj(map[string]any{}),
		},
	}
}

func (s *Server) dispatch(ctx context.Context, name string, args json.RawMessage) (any, error) {
	switch name {
	case ToolLookupHost:
		return s.lookupHost(ctx, args)
	case ToolGetService:
		return s.getService(ctx, args)
	case ToolCountServices:
		return s.countServices(ctx, args)
	case ToolGetHistory:
		return s.getHistory(ctx, args)
	case ToolParseQuery:
		var a struct {
			Query string `json:"query"`
		}
		if err := decodeArgs(args, &a); err != nil {
			return nil, err
		}
		if a.Query == "" {
			return nil, invalidArg("query is required")
		}
		return s.Eng.ParseQuery(ctx, a.Query)
	case ToolSearchServices:
		return s.searchServices(ctx, args)
	case ToolGetQuota:
		if err := decodeArgs(args, &struct{}{}); err != nil {
			return nil, err
		}
		return s.Eng.GetQuota(ctx)
	case ToolCacheStatus:
		// No arguments — which still means "none", not "any".
		if err := decodeArgs(args, &struct{}{}); err != nil {
			return nil, err
		}
		return s.cacheStatus(), nil
	case ToolGetUsage:
		if err := decodeArgs(args, &struct{}{}); err != nil {
			return nil, err
		}
		return rawText(UsageDoc()), nil
	default:
		return nil, &argError{code: CodeUnknownTool, msg: "unknown tool: " + name + " (call get_usage for the tool list)"}
	}
}

func (s *Server) cacheStatus() map[string]any {
	st := s.Cache.Stat()
	return map[string]any{
		"dir":              st.Dir,
		"entries":          st.Entries,
		"bytes":            st.Bytes,
		"host_ttl_hours":   s.Cfg.HostTTL.Hours(),
		"count_ttl_hours":  s.Cfg.CountTTL.Hours(),
		"search_ttl_hours": s.Cfg.SearchTTL.Hours(),
	}
}

// decodeArgs decodes a tool's arguments strictly: an argument the tool does
// not declare is refused by name. Every tool decodes through here. An ignored
// argument is a silent defect — a misspelt `ports` would return every service
// as if it were the filtered answer — and a schema-checking client does not
// save us, because not every client checks.
func decodeArgs(raw json.RawMessage, into any) error {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return &argError{code: CodeInvalidArgument, msg: "arguments: " + err.Error()}
	}
	return nil
}

// argError is a structured tool-layer error: a stable code an agent can branch
// on plus a human-readable message.
type argError struct {
	code string
	msg  string
}

func (e *argError) Error() string { return e.msg }

// structuredError maps an error onto the {code, message} pair an agent sees.
func structuredError(err error) map[string]string {
	var ae *argError
	if errors.As(err, &ae) {
		return map[string]string{"code": ae.code, "message": ae.msg}
	}
	if code := engine.Code(err); code != "" {
		return map[string]string{"code": code, "message": err.Error()}
	}
	return map[string]string{"code": CodeInternal, "message": err.Error()}
}
