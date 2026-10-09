package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/ipaddr"
	"github.com/nlink-jp/shodan-lookup/internal/shodan"
)

// Host is this tool's projection of what Shodan holds for one IP. It is
// complete: every service, every inferred CVE. Large parts of a service (the
// HTML, the certificate chain, CVE summaries) are sections, reached through
// GetService; the projection says how big each one is.
type Host struct {
	IP           string     `json:"ip"`
	Org          string     `json:"org,omitempty"`
	ISP          string     `json:"isp,omitempty"`
	ASN          string     `json:"asn,omitempty"`
	CountryCode  string     `json:"country_code,omitempty"`
	City         string     `json:"city,omitempty"`
	Hostnames    []string   `json:"hostnames,omitempty"`
	Domains      []string   `json:"domains,omitempty"`
	OS           string     `json:"os,omitempty"`
	Tags         []string   `json:"tags,omitempty"`
	LastUpdate   string     `json:"last_update,omitempty"`
	Ports        []int      `json:"ports"`
	ServiceCount int        `json:"service_count"`
	Services     []Service  `json:"services"`
	VulnCount    int        `json:"vuln_count"`
	Vulns        []Vuln     `json:"vulns"`
	Provenance   Provenance `json:"provenance"`
	Notes        []string   `json:"notes,omitempty"`
}

// Service is one banner: what answered on one port, as Shodan last saw it.
type Service struct {
	Port        int      `json:"port"`
	Transport   string   `json:"transport"`
	Module      string   `json:"module,omitempty"`
	Timestamp   string   `json:"timestamp,omitempty"`
	AgeHours    *float64 `json:"observed_hours_ago,omitempty"`
	Product     string   `json:"product,omitempty"`
	Version     string   `json:"version,omitempty"`
	CPE23       []string `json:"cpe23,omitempty"`
	HTTP        *HTTP    `json:"http,omitempty"`
	SSL         *SSL     `json:"ssl,omitempty"`
	Banner      string   `json:"banner"`
	BannerChars int      `json:"banner_chars"`
	FaviconHash *int64   `json:"favicon_hash,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	VulnCount   int      `json:"vuln_count"`
	Sections    []Index  `json:"sections"`
}

// HTTP is the headline of an HTTP service; the page and the headers are
// sections.
type HTTP struct {
	Status    *int   `json:"status,omitempty"`
	Title     string `json:"title,omitempty"`
	Server    string `json:"server,omitempty"`
	Location  string `json:"location,omitempty"`
	HTMLChars int    `json:"html_chars"`
}

// SSL is the headline of a TLS service's certificate; the whole certificate
// and the chain are sections. Expired is computed when the answer is built,
// against ExpiredAsOf — not taken from the observation, which may be old.
type SSL struct {
	SubjectCN   string   `json:"subject_cn,omitempty"`
	IssuerCN    string   `json:"issuer_cn,omitempty"`
	NotBefore   string   `json:"not_before,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	Expired     *bool    `json:"expired,omitempty"`
	ExpiredAsOf string   `json:"expired_as_of,omitempty"`
	SHA1        string   `json:"sha1,omitempty"` // what ssl.cert.fingerprint: matches (measured)
	SHA256      string   `json:"sha256,omitempty"`
	Versions    []string `json:"versions,omitempty"`
}

// Vuln is one CVE Shodan infers for the host from banner versions. Verified
// false — the usual case — means inferred, not confirmed. The summary and
// references are in the service's vulns section; cve-lookup has the rest.
type Vuln struct {
	ID          string   `json:"id"`
	CVSS        *float64 `json:"cvss,omitempty"`
	CVSSVersion *float64 `json:"cvss_version,omitempty"`
	EPSS        *float64 `json:"epss,omitempty"`
	Verified    bool     `json:"verified"`
	Ports       []int    `json:"ports,omitempty"`
}

// Index names one section of a service and its size.
type Index struct {
	Name string `json:"name"`
	Size int    `json:"size"`
	Unit string `json:"unit"` // "chars" or "items"
}

// hostBody is a fetched host record with where it came from.
type hostBody struct {
	ip     string
	entry  *entry
	cached bool
	wire   *wireHost
}

// loadHost gates ip, reads the host record through the cache, and turns a 404
// into an answer only after it has been confirmed.
func (e *Engine) loadHost(ctx context.Context, ipArg string, refresh bool) (*hostBody, error) {
	addr, err := ipaddr.Parse(ipArg)
	if err != nil {
		return nil, err
	}
	if err := e.checkKey(); err != nil {
		return nil, err
	}
	ip := addr.String()
	en, cached, err := e.fetch(ctx, cache.Key("host", ip), e.cfg.HostTTL, refresh,
		func(ctx context.Context) (*shodan.Response, error) { return e.up.Host(ctx, ip) })
	if err != nil {
		return nil, e.hostError(ctx, ip, err)
	}
	var w wireHost
	if err := json.Unmarshal(en.Body, &w); err != nil {
		return nil, &shodan.Error{Code: shodan.CodeDecode, Message: "Shodan's host record for " + ip + " is not the shape this tool reads: " + err.Error()}
	}
	return &hostBody{ip: ip, entry: en, cached: cached, wire: &w}, nil
}

const (
	noInformation = "No information available for that IP."
	invalidIP     = "Invalid IP"
)

// hostError reads a host lookup's failure. The 404 "No information" also comes
// from upstream failing (measured: history lookups of hosts that a count shows
// services for), so it becomes not_indexed only when a credit-free count
// confirms zero services. A failed confirmation is not a negative answer.
func (e *Engine) hostError(ctx context.Context, ip string, err error) error {
	var se *shodan.Error
	if !asShodan(err, &se) || se.Status != 404 {
		return err
	}
	switch se.APIError {
	case invalidIP:
		return invalid(fmt.Sprintf("Shodan does not accept %q as an IP address", ip))
	case noInformation:
	default:
		return err
	}
	n, cerr := e.countIP(ctx, ip)
	switch {
	case cerr != nil:
		return &shodan.Error{Code: shodan.CodeUpstream, Status: 404, Message: fmt.Sprintf(
			"Shodan answered \"no information\" for %s, and the check that would confirm it failed (%s) — this is not evidence that Shodan has not observed it", ip, shodan.Code(cerr))}
	case n > 0:
		return &shodan.Error{Code: shodan.CodeUpstream, Status: 404, Message: fmt.Sprintf(
			"Shodan holds %d service(s) for %s but did not return the record (it answered \"no information\"); retry later — this is not a negative answer", n, ip)}
	default:
		return &Error{Code: CodeNotIndexed, Message: fmt.Sprintf(
			"%s is not in Shodan's index: Shodan has not observed it (a count for ip:%s found 0 services). This is not evidence that nothing is open", ip, ip)}
	}
}

func (e *Engine) countIP(ctx context.Context, ip string) (int, error) {
	resp, err := e.up.Count(ctx, "ip:"+ip, "")
	if err != nil {
		return 0, err
	}
	var c struct {
		Total *int `json:"total"`
	}
	if json.Unmarshal(resp.Body, &c) != nil || c.Total == nil {
		return 0, &shodan.Error{Code: shodan.CodeDecode, Message: "count has no total"}
	}
	return *c.Total, nil
}

// LookupHost returns the complete projection of one IP.
func (e *Engine) LookupHost(ctx context.Context, ip string, refresh bool) (*Host, error) {
	hb, err := e.loadHost(ctx, ip, refresh)
	if err != nil {
		return nil, err
	}
	h := e.project(hb)
	return h, nil
}

// Raw returns the upstream body of a host record, for --raw.
func (e *Engine) Raw(ctx context.Context, ip string, refresh bool) (json.RawMessage, Provenance, error) {
	hb, err := e.loadHost(ctx, ip, refresh)
	if err != nil {
		return nil, Provenance{}, err
	}
	p := provenance(hb.entry, hb.cached)
	p.DocID = docID(hb.entry.Body)
	return hb.entry.Body, p, nil
}

func (e *Engine) project(hb *hostBody) *Host {
	w, now := hb.wire, e.now().UTC()
	h := &Host{
		IP: w.IPStr, Org: str(w.Org), ISP: str(w.ISP), ASN: str(w.ASN), CountryCode: str(w.CountryCode),
		City: str(w.City), Hostnames: w.Hostnames, Domains: w.Domains, OS: str(w.OS), Tags: w.Tags,
		Ports: append([]int{}, w.Ports...), Services: []Service{}, Vulns: []Vuln{},
	}
	if h.IP == "" {
		h.IP = hb.ip
	}
	if t, ok := shodanTime(w.LastUpdate); ok {
		h.LastUpdate = t.Format(time.RFC3339)
	}
	sort.Ints(h.Ports)

	svcs := append([]wireService{}, w.Data...)
	sort.SliceStable(svcs, func(i, j int) bool {
		if svcs[i].Port != svcs[j].Port {
			return svcs[i].Port < svcs[j].Port
		}
		return svcs[i].Transport < svcs[j].Transport
	})
	vulns := map[string]*Vuln{}
	for _, ws := range svcs {
		h.Services = append(h.Services, projectService(ws, now))
		for id, wv := range ws.Vulns {
			v, ok := vulns[id]
			if !ok {
				v = &Vuln{ID: id, CVSS: wv.CVSS, CVSSVersion: wv.CVSSVersion, EPSS: wv.EPSS, Verified: wv.Verified}
				vulns[id] = v
			}
			v.Verified = v.Verified || wv.Verified
			v.Ports = appendUnique(v.Ports, ws.Port)
		}
	}
	// A CVE the host lists without a scored entry in any service still counts.
	for _, id := range w.Vulns {
		if _, ok := vulns[id]; !ok {
			vulns[id] = &Vuln{ID: id}
		}
	}
	for _, v := range vulns {
		h.Vulns = append(h.Vulns, *v)
	}
	sort.Slice(h.Vulns, func(i, j int) bool {
		a, b := score(h.Vulns[i].CVSS), score(h.Vulns[j].CVSS)
		if a != b {
			return a > b
		}
		return h.Vulns[i].ID < h.Vulns[j].ID
	})
	h.ServiceCount, h.VulnCount = len(h.Services), len(h.Vulns)
	h.Provenance = provenance(hb.entry, hb.cached)
	h.Provenance.DocID = docID(hb.entry.Body)
	if h.VulnCount == 0 {
		h.Notes = append(h.Notes, "no CVEs inferred — Shodan infers vulnerabilities from banner versions; an empty list is not evidence of none")
	} else {
		h.Notes = append(h.Notes, "vulns are inferred from banner versions; verified:false means inferred, not confirmed. cve-lookup has the context for each ID")
	}
	return h
}

func projectService(ws wireService, now time.Time) Service {
	s := Service{
		Port: ws.Port, Transport: ws.Transport, Module: ws.Shodan.Module, Product: str(ws.Product),
		Version: str(ws.Version), CPE23: ws.CPE23, Banner: ws.Data, BannerChars: runeCount(ws.Data),
		Tags: ws.Tags, VulnCount: len(ws.Vulns),
	}
	if t, ok := shodanTime(ws.Timestamp); ok {
		s.Timestamp = t.Format(time.RFC3339)
		age := math.Round(now.Sub(t).Hours()*10) / 10
		s.AgeHours = &age
	}
	s.Sections = append(s.Sections, Index{Name: SectionBanner, Size: s.BannerChars, Unit: unitChars})
	if ws.HTTP != nil {
		hh := &HTTP{Status: ws.HTTP.Status, Title: str(ws.HTTP.Title), Server: str(ws.HTTP.Server),
			Location: str(ws.HTTP.Location), HTMLChars: runeCount(str(ws.HTTP.HTML))}
		s.HTTP = hh
		if ws.HTTP.Favicon != nil {
			s.FaviconHash = ws.HTTP.Favicon.Hash
		}
		s.Sections = append(s.Sections,
			Index{Name: SectionHTML, Size: hh.HTMLChars, Unit: unitChars},
			Index{Name: SectionHeaders, Size: len(ws.HTTP.Headers), Unit: unitItems})
	}
	if ws.SSL != nil {
		s.SSL = projectSSL(ws.SSL, now)
		s.Sections = append(s.Sections,
			Index{Name: SectionCert, Size: runeCount(certText(ws.SSL)), Unit: unitChars},
			Index{Name: SectionChain, Size: len(ws.SSL.Chain), Unit: unitItems})
	}
	if len(ws.Vulns) > 0 {
		s.Sections = append(s.Sections, Index{Name: SectionVulns, Size: len(ws.Vulns), Unit: unitItems})
	}
	return s
}

func projectSSL(ws *wireSSL, now time.Time) *SSL {
	out := &SSL{Versions: ws.Versions}
	var c wireCert
	if len(ws.Cert) == 0 || json.Unmarshal(ws.Cert, &c) != nil {
		return out
	}
	out.SubjectCN, out.IssuerCN = nameField(c.Subject, "CN"), nameField(c.Issuer, "CN")
	out.SHA1, out.SHA256 = c.Fingerprint.SHA1, c.Fingerprint.SHA256
	if t, ok := certTime(c.Issued); ok {
		out.NotBefore = t.Format(time.RFC3339)
	}
	if t, ok := certTime(c.Expires); ok {
		out.NotAfter = t.Format(time.RFC3339)
		expired := now.After(t)
		out.Expired, out.ExpiredAsOf = &expired, now.Format(time.RFC3339)
	}
	return out
}

func score(p *float64) float64 {
	if p == nil {
		return -1
	}
	return *p
}

func appendUnique(xs []int, x int) []int {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	return append(xs, x)
}

func runeCount(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}
