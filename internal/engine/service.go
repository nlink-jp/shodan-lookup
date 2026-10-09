package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/nlink-jp/shodan-lookup/internal/shodan"
)

// Section names. A section is one large part of one service, paged in full.
const (
	SectionBanner  = "banner"
	SectionHTML    = "http_html"
	SectionHeaders = "http_headers"
	SectionCert    = "ssl_cert"
	SectionChain   = "ssl_chain"
	SectionVulns   = "vulns"

	unitChars = "chars"
	unitItems = "items"
)

// Sections lists every section name, in the order a service lists them.
var Sections = []string{SectionBanner, SectionHTML, SectionHeaders, SectionCert, SectionChain, SectionVulns}

// Paging bounds. Text is paged by characters, never bytes.
const (
	DefaultTextLimit = 4000
	MaxTextLimit     = 20000
	DefaultListLimit = 50
	MaxListLimit     = 200
)

// Page is one page of one section of one service.
type Page struct {
	IP         string     `json:"ip"`
	Port       int        `json:"port"`
	Transport  string     `json:"transport"`
	Section    string     `json:"section"`
	Unit       string     `json:"unit"`
	Total      int        `json:"total"`
	Offset     int        `json:"offset"`
	Text       string     `json:"text,omitempty"`
	Items      []any      `json:"items,omitempty"`
	NextOffset *int       `json:"next_offset,omitempty"`
	Provenance Provenance `json:"provenance"`
	Notes      []string   `json:"notes,omitempty"`
}

// SectionVuln is one entry of the vulns section: the projection's fields plus
// what the projection leaves out.
type SectionVuln struct {
	ID          string   `json:"id"`
	CVSS        *float64 `json:"cvss,omitempty"`
	CVSSVersion *float64 `json:"cvss_version,omitempty"`
	EPSS        *float64 `json:"epss,omitempty"`
	Verified    bool     `json:"verified"`
	Summary     string   `json:"summary,omitempty"`
	References  []string `json:"references,omitempty"`
}

// ServiceQuery names one page of one section.
type ServiceQuery struct {
	IP        string
	Port      int
	Transport string // "", "tcp" or "udp"
	Section   string
	Offset    int
	Limit     int // 0: the section kind's default
}

// GetService returns one page of one section of one service. The host record
// comes from the cache when it is fresh and is fetched when it is not; the
// page carries the record's doc_id, so a caller paging through a section can
// tell that the record underneath changed between two pages.
func (e *Engine) GetService(ctx context.Context, q ServiceQuery, refresh bool) (*Page, error) {
	if !contains(Sections, q.Section) {
		return nil, invalid(fmt.Sprintf("section %q is not one of %s", q.Section, strings.Join(Sections, ", ")))
	}
	if q.Port < 1 || q.Port > 65535 {
		return nil, invalid(fmt.Sprintf("port %d is not between 1 and 65535", q.Port))
	}
	if q.Transport != "" && q.Transport != "tcp" && q.Transport != "udp" {
		return nil, invalid(fmt.Sprintf("transport %q is not tcp or udp", q.Transport))
	}
	if q.Offset < 0 {
		return nil, invalid("offset must not be negative")
	}
	hb, err := e.loadHost(ctx, q.IP, refresh)
	if err != nil {
		return nil, err
	}

	var match []wireService
	for _, s := range hb.wire.Data {
		if s.Port == q.Port && (q.Transport == "" || s.Transport == q.Transport) {
			match = append(match, s)
		}
	}
	switch {
	case len(match) == 0:
		return nil, &Error{Code: CodeNotObserved, Message: fmt.Sprintf(
			"Shodan has no banner for %s port %d%s (observed ports: %v) — not evidence that the port is closed", hb.ip, q.Port, transportSuffix(q.Transport), sortedPorts(hb.wire))}
	case len(match) > 1:
		var ts []string
		for _, s := range match {
			ts = append(ts, s.Transport)
		}
		sort.Strings(ts)
		return nil, invalid(fmt.Sprintf("%s port %d has more than one service (%s); pass transport", hb.ip, q.Port, strings.Join(ts, ", ")))
	}
	s := match[0]

	p := &Page{IP: hb.ip, Port: s.Port, Transport: s.Transport, Section: q.Section, Offset: q.Offset}
	p.Provenance = provenance(hb.entry, hb.cached)
	p.Provenance.DocID = docID(hb.entry.Body)

	switch q.Section {
	case SectionBanner:
		err = pageText(p, s.Data, q.Limit)
	case SectionHTML:
		if s.HTTP == nil {
			return emptySection(p, "this service has no HTTP data"), nil
		}
		err = pageText(p, str(s.HTTP.HTML), q.Limit)
	case SectionCert:
		if s.SSL == nil {
			return emptySection(p, "this service has no TLS data"), nil
		}
		err = pageText(p, certText(s.SSL), q.Limit)
	case SectionHeaders:
		if s.HTTP == nil {
			return emptySection(p, "this service has no HTTP data"), nil
		}
		names := make([]string, 0, len(s.HTTP.Headers))
		for n := range s.HTTP.Headers {
			names = append(names, n)
		}
		sort.Strings(names)
		items := make([]any, 0, len(names))
		for _, n := range names {
			items = append(items, n+": "+headerValue(s.HTTP.Headers[n]))
		}
		err = pageItems(p, items, q.Limit)
	case SectionChain:
		if s.SSL == nil {
			return emptySection(p, "this service has no TLS data"), nil
		}
		items := make([]any, 0, len(s.SSL.Chain))
		for _, c := range s.SSL.Chain {
			items = append(items, c)
		}
		err = pageItems(p, items, q.Limit)
	case SectionVulns:
		ids := make([]string, 0, len(s.Vulns))
		for id := range s.Vulns {
			ids = append(ids, id)
		}
		sort.Strings(ids) // a fixed order, so pages do not shift between calls
		items := make([]any, 0, len(ids))
		for _, id := range ids {
			v := s.Vulns[id]
			items = append(items, SectionVuln{ID: id, CVSS: v.CVSS, CVSSVersion: v.CVSSVersion, EPSS: v.EPSS,
				Verified: v.Verified, Summary: v.Summary, References: v.References})
		}
		if len(items) == 0 {
			return emptySection(p, "Shodan infers no CVEs for this service — not evidence of none"), nil
		}
		err = pageItems(p, items, q.Limit)
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

func pageText(p *Page, text string, limit int) error {
	if limit == 0 {
		limit = DefaultTextLimit
	}
	if limit < 1 || limit > MaxTextLimit {
		return invalid(fmt.Sprintf("limit for a text section must be between 1 and %d characters", MaxTextLimit))
	}
	r := []rune(text)
	p.Unit, p.Total = unitChars, len(r)
	if p.Offset > len(r) {
		return invalid(fmt.Sprintf("offset %d is past the end of the section (%d characters)", p.Offset, len(r)))
	}
	end := min(p.Offset+limit, len(r))
	p.Text = string(r[p.Offset:end])
	if end < len(r) {
		p.NextOffset = &end
	}
	return nil
}

func pageItems(p *Page, items []any, limit int) error {
	if limit == 0 {
		limit = DefaultListLimit
	}
	if limit < 1 || limit > MaxListLimit {
		return invalid(fmt.Sprintf("limit for a list section must be between 1 and %d items", MaxListLimit))
	}
	p.Unit, p.Total = unitItems, len(items)
	if p.Offset > len(items) {
		return invalid(fmt.Sprintf("offset %d is past the end of the section (%d items)", p.Offset, len(items)))
	}
	end := min(p.Offset+limit, len(items))
	p.Items = items[p.Offset:end]
	if end < len(items) {
		p.NextOffset = &end
	}
	return nil
}

func emptySection(p *Page, note string) *Page {
	p.Unit, p.Total = unitItems, 0
	p.Notes = append(p.Notes, note)
	return p
}

// certText is the whole certificate object as indented JSON — the ssl_cert
// section. It is what Shodan holds, re-indented and nothing else: the bytes
// are not decoded into Go values first, because the serial arrives as a JSON
// number too large for a float64 and would come back altered.
func certText(s *wireSSL) string {
	if len(s.Cert) == 0 {
		return ""
	}
	var b bytes.Buffer
	if json.Indent(&b, s.Cert, "", "  ") != nil {
		return string(s.Cert)
	}
	return b.String()
}

func sortedPorts(w *wireHost) []int {
	ports := append([]int{}, w.Ports...)
	sort.Ints(ports)
	return ports
}

func transportSuffix(t string) string {
	if t == "" {
		return ""
	}
	return "/" + t
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func asShodan(err error, out **shodan.Error) bool { return errors.As(err, out) }
