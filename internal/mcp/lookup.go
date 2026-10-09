package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/nlink-jp/shodan-lookup/internal/engine"
)

// MCP bounds, tighter than the engine's: they are what one tool result may
// cost in a client's context. A caller that sends a value past one is
// refused; a default past one is clamped.
const (
	mcpMaxTextLimit = 16000 // characters; even fully escaped, under the result ceiling
	mcpMaxListLimit = 50
	mcpDefaultList  = 20
	mcpMaxFacetN    = 100
	mcpMaxPorts     = 50
	mcpMaxNames     = 50 // hostnames and domains each
	// softBudget is where lookup_host starts dropping services rather than
	// let the result be withheld whole at maxResultBytes.
	softBudget = 112 << 10
)

// compactHost is lookup_host's answer: the engine's projection with the
// response budget applied. What was dropped is counted in Omitted — only when
// something was.
type compactHost struct {
	*engine.Host
	PortsNotObserved []int          `json:"ports_not_observed,omitempty"`
	Omitted          map[string]int `json:"omitted,omitempty"`
}

type lookupArgs struct {
	IP        string `json:"ip"`
	Ports     []int  `json:"ports"`
	PortsOnly bool   `json:"ports_only"`
	Refresh   bool   `json:"refresh"`
}

func (s *Server) lookupHost(ctx context.Context, raw json.RawMessage) (any, error) {
	var a lookupArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if a.IP == "" {
		return nil, invalidArg("ip is required")
	}
	if a.PortsOnly && len(a.Ports) > 0 {
		return nil, invalidArg("ports and ports_only do not combine: ports_only lists no services")
	}
	if len(a.Ports) > mcpMaxPorts {
		return nil, invalidArg(fmt.Sprintf("ports lists at most %d ports", mcpMaxPorts))
	}
	for _, p := range a.Ports {
		if p < 1 || p > 65535 {
			return nil, invalidArg(fmt.Sprintf("port %d is not between 1 and 65535", p))
		}
	}
	h, err := s.Eng.LookupHost(ctx, a.IP, a.Refresh)
	if err != nil {
		return nil, err
	}
	return s.compact(h, a.Ports, a.PortsOnly), nil
}

func (s *Server) compact(h *engine.Host, ports []int, portsOnly bool) *compactHost {
	out := &compactHost{Host: h, Omitted: map[string]int{}}
	// Names are listed up to a cap, whatever else is asked: a shared host can
	// carry thousands, and no other field would bound them.
	if n := len(h.Hostnames) - mcpMaxNames; n > 0 {
		h.Hostnames, out.Omitted["hostnames"] = h.Hostnames[:mcpMaxNames], n
	}
	if n := len(h.Domains) - mcpMaxNames; n > 0 {
		h.Domains, out.Omitted["domains"] = h.Domains[:mcpMaxNames], n
	}
	if portsOnly {
		out.Omitted["services"] = len(h.Services)
		out.Omitted["vulns"] = len(h.Vulns)
		h.Services, h.Vulns = []engine.Service{}, []engine.Vuln{}
		h.Notes = append(h.Notes, "ports_only: services and vulns are counted, not listed; ask again without ports_only, or get_service for one port")
		return finish(out)
	}

	if len(ports) > 0 {
		want := map[int]bool{}
		for _, p := range ports {
			want[p] = true
		}
		kept := []engine.Service{}
		seen := map[int]bool{}
		for _, sv := range h.Services {
			if want[sv.Port] {
				kept = append(kept, sv)
				seen[sv.Port] = true
			}
		}
		for p := range want {
			if !seen[p] {
				out.PortsNotObserved = append(out.PortsNotObserved, p)
			}
		}
		sort.Ints(out.PortsNotObserved)
		if n := len(h.Services) - len(kept); n > 0 {
			out.Omitted["services_not_asked_for"] = n
		}
		h.Services = kept
		if len(out.PortsNotObserved) > 0 {
			h.Notes = append(h.Notes, "ports_not_observed: Shodan has no banner for these ports — not evidence that they are closed")
		}
	}

	if limit := s.Cfg.DefaultServices; limit > 0 && len(h.Services) > limit {
		out.Omitted["services"] += len(h.Services) - limit
		h.Services = h.Services[:limit]
	}
	clipped := 0
	for i := range h.Services {
		if b, cut := clipEscaped(h.Services[i].Banner, s.Cfg.BannerBytes); cut {
			h.Services[i].Banner = b
			clipped++
		}
	}
	if clipped > 0 {
		out.Omitted["banners_shortened"] = clipped
		h.Notes = append(h.Notes, fmt.Sprintf("%d banner(s) shortened to %d bytes; banner_chars is the full length, and get_service section banner returns it whole", clipped, s.Cfg.BannerBytes))
	}
	if limit := s.Cfg.DefaultVulns; limit > 0 && len(h.Vulns) > limit {
		out.Omitted["vulns"] = len(h.Vulns) - limit
		h.Vulns = h.Vulns[:limit]
		h.Notes = append(h.Notes, fmt.Sprintf("only the %d highest-CVSS CVEs are listed; vuln_count is the total, and get_service section vulns lists each service's in full", limit))
	}

	// Last resort before the ceiling: drop services from the end, then CVEs,
	// counted. The size is measured as the ceiling measures it — indented,
	// after the 1000-character backstop — or the thinning would run against a
	// different number from the one that withholds the result.
	capStrings(out)
	for over(out) && len(h.Services) > 1 {
		drop := (len(h.Services) + 1) / 2
		out.Omitted["services"] += drop
		h.Services = h.Services[:len(h.Services)-drop]
	}
	for over(out) && len(h.Vulns) > 1 {
		drop := (len(h.Vulns) + 1) / 2
		out.Omitted["vulns"] += drop
		h.Vulns = h.Vulns[:len(h.Vulns)-drop]
	}
	return finish(out)
}

// over reports whether v, encoded as toolText encodes it, passes the soft
// budget.
func over(v any) bool {
	b, err := json.MarshalIndent(v, "", "  ")
	return err == nil && len(b) > softBudget
}

func finish(out *compactHost) *compactHost {
	for k, v := range out.Omitted {
		if v == 0 {
			delete(out.Omitted, k)
		}
	}
	if out.Omitted["services"] > 0 {
		out.Notes = append(out.Notes, "services were left out (omitted.services); ask with ports to see them, or get_service for one")
	}
	if len(out.Omitted) == 0 {
		out.Omitted = nil
	}
	return out
}

// clipEscaped shortens s so that its JSON-escaped form fits in max bytes,
// cutting on a character boundary. Escaping is what the client pays for: a
// banner of control characters is six bytes per character on the wire.
func clipEscaped(s string, max int) (string, bool) {
	if max <= 0 || escapedLen(s) <= max {
		return s, false
	}
	n, end := 0, 0
	for i, r := range s {
		w := escapedRuneLen(r)
		if n+w > max {
			break
		}
		n += w
		end = i + utf8.RuneLen(r)
	}
	return s[:end] + "…", true
}

func escapedLen(s string) int {
	n := 0
	for _, r := range s {
		n += escapedRuneLen(r)
	}
	return n
}

func escapedRuneLen(r rune) int {
	switch {
	case r == '"' || r == '\\' || r == '\n' || r == '\r' || r == '\t':
		return 2
	case r < 0x20 || r == '<' || r == '>' || r == '&' || r == 0x2028 || r == 0x2029:
		return 6
	case r == utf8.RuneError:
		return 6
	default:
		return utf8.RuneLen(r)
	}
}

type serviceArgs struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Section   string `json:"section"`
	Offset    int    `json:"offset"`
	Limit     *int   `json:"limit"`
	Refresh   bool   `json:"refresh"`
}

var textSections = map[string]bool{engine.SectionBanner: true, engine.SectionHTML: true, engine.SectionCert: true}

func (s *Server) getService(ctx context.Context, raw json.RawMessage) (any, error) {
	var a serviceArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if a.IP == "" || a.Section == "" || a.Port == 0 {
		return nil, invalidArg("ip, port and section are required")
	}
	limit := 0
	if a.Limit != nil {
		limit = *a.Limit
		max := mcpMaxListLimit
		if textSections[a.Section] {
			max = mcpMaxTextLimit
		}
		if limit < 1 || limit > max {
			return nil, invalidArg(fmt.Sprintf("limit for section %s must be between 1 and %d", a.Section, max))
		}
	} else if !textSections[a.Section] {
		limit = mcpDefaultList
	}
	return s.Eng.GetService(ctx, engine.ServiceQuery{IP: a.IP, Port: a.Port, Transport: a.Transport,
		Section: a.Section, Offset: a.Offset, Limit: limit}, a.Refresh)
}

type countArgs struct {
	Query   string   `json:"query"`
	Facets  []string `json:"facets"`
	Refresh bool     `json:"refresh"`
}

func (s *Server) countServices(ctx context.Context, raw json.RawMessage) (any, error) {
	var a countArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if strings.TrimSpace(a.Query) == "" {
		return nil, invalidArg("query is required")
	}
	specs := make([]engine.FacetSpec, 0, len(a.Facets))
	for _, f := range a.Facets {
		spec, err := engine.ParseFacet(f)
		if err != nil {
			return nil, err
		}
		if spec.N > mcpMaxFacetN {
			return nil, invalidArg(fmt.Sprintf("facet %q: at most %d values per facet here (the CLI allows %d)", f, mcpMaxFacetN, engine.MaxFacetValues))
		}
		specs = append(specs, spec)
	}
	return s.Eng.CountServices(ctx, a.Query, specs, a.Refresh)
}

func invalidArg(msg string) error { return &argError{code: CodeInvalidArgument, msg: msg} }

// mcpMaxVariants is how many variants get_history lists per port; the rest
// are counted.
const mcpMaxVariants = 20

// compactHistory is get_history's answer: the engine's history with the
// variants per port capped and the cap counted.
type compactHistory struct {
	*engine.History
	Omitted map[string]int `json:"omitted,omitempty"`
}

type historyArgs struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Offset    int    `json:"offset"`
	Limit     *int   `json:"limit"`
	Refresh   bool   `json:"refresh"`
}

func (s *Server) getHistory(ctx context.Context, raw json.RawMessage) (any, error) {
	var a historyArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if a.IP == "" {
		return nil, invalidArg("ip is required")
	}
	limit := mcpDefaultList
	if a.Limit != nil {
		if *a.Limit < 1 || *a.Limit > mcpMaxListLimit {
			return nil, invalidArg(fmt.Sprintf("limit must be between 1 and %d", mcpMaxListLimit))
		}
		limit = *a.Limit
	}
	if a.Port == 0 && (a.Transport != "" || a.Offset != 0 || a.Limit != nil) {
		return nil, invalidArg("transport, offset and limit apply to one port's observations; pass port")
	}
	h, err := s.Eng.GetHistory(ctx, engine.HistoryQuery{IP: a.IP, Port: a.Port, Transport: a.Transport, Offset: a.Offset, Limit: limit}, a.Refresh)
	if err != nil {
		return nil, err
	}
	out := &compactHistory{History: h}
	dropped := 0
	for i := range h.Ports {
		if n := len(h.Ports[i].Variants); n > mcpMaxVariants {
			// Keep the newest variants: they are what the port answers with now.
			h.Ports[i].Variants = h.Ports[i].Variants[n-mcpMaxVariants:]
			dropped += n - mcpMaxVariants
		}
	}
	// A host with hundreds of ports: fewer variants per port first, then
	// fewer ports, each counted, before the ceiling would withhold it all.
	capStrings(out)
	for keep := mcpMaxVariants / 4; over(out) && keep >= 1; keep /= 4 {
		for i := range h.Ports {
			if n := len(h.Ports[i].Variants); n > keep {
				h.Ports[i].Variants = h.Ports[i].Variants[n-keep:]
				dropped += n - keep
			}
		}
		if keep == 1 {
			break
		}
	}
	droppedPorts := 0
	for over(out) && len(h.Ports) > 1 {
		drop := (len(h.Ports) + 1) / 2
		droppedPorts += drop
		h.Ports = h.Ports[:len(h.Ports)-drop]
	}
	if dropped > 0 || droppedPorts > 0 {
		out.Omitted = map[string]int{}
		if dropped > 0 {
			out.Omitted["variants"] = dropped
			h.Notes = append(h.Notes, "not every variant is listed (variant_count is each port's total; the most recent are kept); pass port to page its observations")
		}
		if droppedPorts > 0 {
			out.Omitted["ports"] = droppedPorts
			h.Notes = append(h.Notes, "not every port is listed; pass port for one of them")
		}
	}
	return out, nil
}
