package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/ipaddr"
	"github.com/nlink-jp/shodan-lookup/internal/shodan"
)

// HistoryCap is the most banners Shodan returns for a host's history
// (measured: exactly 1,000 for three hosts).
const HistoryCap = 1000

// History is a host's past as Shodan returns it: a window of the latest
// banners, summarised per port as the variants that were seen and when. It
// is complete; the MCP layer caps the variants it lists.
type History struct {
	IP         string            `json:"ip"`
	Window     HistoryWindow     `json:"window"`
	Ports      []PortHistory     `json:"ports"`
	Port       *ObservationsPage `json:"observations,omitempty"`
	Provenance Provenance        `json:"provenance"`
	Notes      []string          `json:"notes,omitempty"`
}

// HistoryWindow is what the history covers. Nothing before Oldest can be read
// when Capped; below the cap, whether this is all Shodan keeps is unknown.
type HistoryWindow struct {
	Oldest   string    `json:"oldest,omitempty"`
	Newest   string    `json:"newest,omitempty"`
	Banners  int       `json:"banners"`
	Cap      int       `json:"cap"`
	Capped   bool      `json:"capped"`
	Dominant *Dominant `json:"dominated_by,omitempty"`
}

// Dominant is the port that fills half the window or more.
type Dominant struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Banners   int    `json:"banners"`
}

// PortHistory is one port's history inside the window.
type PortHistory struct {
	Port         int       `json:"port"`
	Transport    string    `json:"transport"`
	Observations int       `json:"observations"`
	FirstSeen    string    `json:"first_seen"`
	LastSeen     string    `json:"last_seen"`
	VariantCount int       `json:"variant_count"`
	Variants     []Variant `json:"variants"`
}

// Variant is one distinct combination of what a port answered with, and when
// it was seen. A new variant is a change: a product, a version, a page title
// or a certificate.
type Variant struct {
	Product      string `json:"product,omitempty"`
	Version      string `json:"version,omitempty"`
	Title        string `json:"title,omitempty"`
	CertSHA1     string `json:"cert_sha1,omitempty"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	Observations int    `json:"observations"`
}

// Observation is one historical banner, as a line.
type Observation struct {
	Timestamp   string `json:"timestamp"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
	Title       string `json:"title,omitempty"`
	CertSHA1    string `json:"cert_sha1,omitempty"`
	FirstLine   string `json:"banner_first_line,omitempty"`
	BannerChars int    `json:"banner_chars"`
}

// ObservationsPage is one page of one port's observations, newest first.
type ObservationsPage struct {
	Port       int           `json:"port"`
	Transport  string        `json:"transport"`
	Total      int           `json:"total"`
	Offset     int           `json:"offset"`
	Items      []Observation `json:"items"`
	NextOffset *int          `json:"next_offset,omitempty"`
}

// HistoryQuery asks for a host's history, and optionally one port's
// observations.
type HistoryQuery struct {
	IP        string
	Port      int // 0: the summary only
	Transport string
	Offset    int
	Limit     int // 0: DefaultListLimit
}

type histBanner struct {
	wireService
	ts time.Time
}

// GetHistory returns a host's history. A 404 is cross-checked as for the
// current record: Shodan does not return the history of some hosts it holds
// services for (measured), and that is never reported as "not indexed".
func (e *Engine) GetHistory(ctx context.Context, q HistoryQuery, refresh bool) (*History, error) {
	if q.Port < 0 || q.Port > 65535 {
		return nil, invalid(fmt.Sprintf("port %d is not between 1 and 65535", q.Port))
	}
	if q.Transport != "" && q.Transport != "tcp" && q.Transport != "udp" {
		return nil, invalid(fmt.Sprintf("transport %q is not tcp or udp", q.Transport))
	}
	if q.Offset < 0 {
		return nil, invalid("offset must not be negative")
	}
	limit := q.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	if limit < 1 || limit > MaxListLimit {
		return nil, invalid(fmt.Sprintf("limit must be between 1 and %d observations", MaxListLimit))
	}
	ip, en, cached, w, err := e.loadHistory(ctx, q.IP, refresh)
	if err != nil {
		return nil, err
	}

	h := &History{IP: ip, Ports: []PortHistory{}, Provenance: provenance(en, cached)}
	h.Provenance.DocID = docID(en.Body)
	banners := make([]histBanner, 0, len(w.Data))
	for _, ws := range w.Data {
		t, ok := shodanTime(ws.Timestamp)
		if !ok {
			continue // a banner without a readable time cannot be placed in a timeline
		}
		banners = append(banners, histBanner{ws, t})
	}
	sort.SliceStable(banners, func(i, j int) bool { return banners[i].ts.After(banners[j].ts) })
	h.Window = HistoryWindow{Banners: len(w.Data), Cap: HistoryCap, Capped: len(w.Data) >= HistoryCap}
	if n := len(w.Data) - len(banners); n > 0 {
		h.Notes = append(h.Notes, fmt.Sprintf("%d banner(s) had no readable timestamp and are left out of the timeline", n))
	}
	if len(banners) > 0 {
		h.Window.Newest = banners[0].ts.Format(time.RFC3339)
		h.Window.Oldest = banners[len(banners)-1].ts.Format(time.RFC3339)
	}

	byPort := map[string][]histBanner{}
	for _, b := range banners {
		k := portKey(b.Port, b.Transport)
		byPort[k] = append(byPort[k], b)
	}
	for _, bs := range byPort {
		h.Ports = append(h.Ports, summarisePort(bs))
	}
	sort.Slice(h.Ports, func(i, j int) bool {
		if h.Ports[i].Port != h.Ports[j].Port {
			return h.Ports[i].Port < h.Ports[j].Port
		}
		return h.Ports[i].Transport < h.Ports[j].Transport
	})
	for _, p := range h.Ports {
		if len(banners) > 0 && 2*p.Observations >= len(banners) && len(banners) >= 20 {
			h.Window.Dominant = &Dominant{Port: p.Port, Transport: p.Transport, Banners: p.Observations}
			break
		}
	}

	if h.Window.Capped {
		h.Notes = append(h.Notes, fmt.Sprintf("Shodan returns at most the latest %d banners: this window starts at %s and nothing earlier can be read here. A port's first_seen is its first sighting inside the window, not when it opened", HistoryCap, h.Window.Oldest))
	} else {
		h.Notes = append(h.Notes, fmt.Sprintf("Shodan returned %d banners, under its %d cap; whether that is all the history it keeps is not documented", h.Window.Banners, HistoryCap))
	}
	if d := h.Window.Dominant; d != nil {
		h.Notes = append(h.Notes, fmt.Sprintf("%d/%s holds %d of the %d banners; the window is short because of it", d.Port, d.Transport, d.Banners, len(banners)))
	}
	h.Notes = append(h.Notes, "a new variant is a change in product, version, page title or certificate; the CLI's history --raw holds every banner in full")

	if q.Port != 0 {
		page, err := observationsPage(byPort, q, limit, h.Window)
		if err != nil {
			return nil, err
		}
		h.Port = page
	}
	return h, nil
}

// loadHistory gates ip and reads its history through the cache, turning a
// 404 into an answer only after it has been confirmed.
func (e *Engine) loadHistory(ctx context.Context, ipArg string, refresh bool) (string, *entry, bool, *wireHost, error) {
	addr, err := ipaddr.Parse(ipArg)
	if err != nil {
		return "", nil, false, nil, err
	}
	if err := e.checkKey(); err != nil {
		return "", nil, false, nil, err
	}
	ip := addr.String()
	en, cached, err := e.fetch(ctx, cache.Key("history", ip), e.cfg.HostTTL, refresh,
		func(ctx context.Context) (*shodan.Response, error) { return e.up.HostHistory(ctx, ip) }, validHost)
	if err != nil {
		return "", nil, false, nil, e.hostError(ctx, ip, err, "its history")
	}
	var w wireHost
	if err := json.Unmarshal(en.Body, &w); err != nil {
		return "", nil, false, nil, &shodan.Error{Code: shodan.CodeDecode, Message: "Shodan's history for " + ip + " is not the shape this tool reads: " + err.Error()}
	}
	return ip, en, cached, &w, nil
}

// RawHistory returns the upstream body of a host's history, for --raw: every
// historical banner in full.
func (e *Engine) RawHistory(ctx context.Context, ip string, refresh bool) (json.RawMessage, error) {
	_, en, _, _, err := e.loadHistory(ctx, ip, refresh)
	if err != nil {
		return nil, err
	}
	return en.Body, nil
}

func portKey(port int, transport string) string { return fmt.Sprintf("%d/%s", port, transport) }

// summarisePort reads one port's banners, newest first, into its sightings
// and variants.
func summarisePort(bs []histBanner) PortHistory {
	p := PortHistory{Port: bs[0].Port, Transport: bs[0].Transport, Observations: len(bs),
		LastSeen: bs[0].ts.Format(time.RFC3339), FirstSeen: bs[len(bs)-1].ts.Format(time.RFC3339), Variants: []Variant{}}
	type vk struct{ product, version, title, sha1 string }
	index := map[vk]int{}
	for i := len(bs) - 1; i >= 0; i-- { // oldest first, so variants come out in the order they appeared
		b := bs[i]
		k := vk{str(b.Product), str(b.Version), httpTitle(b.wireService), certSHA1(b.wireService)}
		at := b.ts.Format(time.RFC3339)
		j, ok := index[k]
		if !ok {
			index[k] = len(p.Variants)
			p.Variants = append(p.Variants, Variant{Product: k.product, Version: k.version, Title: k.title, CertSHA1: k.sha1, FirstSeen: at, LastSeen: at})
			j = len(p.Variants) - 1
		}
		p.Variants[j].LastSeen = at
		p.Variants[j].Observations++
	}
	p.VariantCount = len(p.Variants)
	return p
}

func observationsPage(byPort map[string][]histBanner, q HistoryQuery, limit int, w HistoryWindow) (*ObservationsPage, error) {
	var keys []string
	for k, bs := range byPort {
		if bs[0].Port == q.Port && (q.Transport == "" || bs[0].Transport == q.Transport) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	switch {
	case len(keys) == 0:
		return nil, &Error{Code: CodeNotObserved, Message: fmt.Sprintf(
			"Shodan's history has no banner for port %d%s between %s and %s — not evidence that the port was closed", q.Port, transportSuffix(q.Transport), orUnknown(w.Oldest), orUnknown(w.Newest))}
	case len(keys) > 1:
		return nil, invalid(fmt.Sprintf("port %d has history on more than one transport (%s); pass transport", q.Port, strings.Join(keys, ", ")))
	}
	bs := byPort[keys[0]]
	page := &ObservationsPage{Port: bs[0].Port, Transport: bs[0].Transport, Total: len(bs), Offset: q.Offset, Items: []Observation{}}
	if q.Offset > len(bs) {
		return nil, invalid(fmt.Sprintf("offset %d is past the end (%d observations)", q.Offset, len(bs)))
	}
	end := min(q.Offset+limit, len(bs))
	for _, b := range bs[q.Offset:end] {
		page.Items = append(page.Items, Observation{Timestamp: b.ts.Format(time.RFC3339), Product: str(b.Product),
			Version: str(b.Version), Title: httpTitle(b.wireService), CertSHA1: certSHA1(b.wireService),
			FirstLine: firstLine(b.Data), BannerChars: runeCount(b.Data)})
	}
	if end < len(bs) {
		page.NextOffset = &end
	}
	return page, nil
}

func httpTitle(ws wireService) string {
	if ws.HTTP == nil {
		return ""
	}
	return str(ws.HTTP.Title)
}

func certSHA1(ws wireService) string {
	if ws.SSL == nil || len(ws.SSL.Cert) == 0 {
		return ""
	}
	var c wireCert
	if json.Unmarshal(ws.SSL.Cert, &c) != nil {
		return ""
	}
	return c.Fingerprint.SHA1
}

// firstLine is the first non-blank line of a banner — a DNS banner starts with
// an empty one — clipped for a one-line listing.
func firstLine(banner string) string {
	for _, l := range strings.Split(banner, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			if r := []rune(t); len(r) > 200 {
				return string(r[:200]) + "…"
			}
			return t
		}
	}
	return ""
}

func orUnknown(s string) string {
	if s == "" {
		return "(no dated banners)"
	}
	return s
}
