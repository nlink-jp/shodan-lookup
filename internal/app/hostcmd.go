package app

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/nlink-jp/shodan-lookup/internal/engine"
)

func runHost(args []string, version string, stdout, stderr io.Writer) int {
	var c common
	var raw, portsOnly bool
	var ports multiInt
	fs := flag.NewFlagSet("host", flag.ContinueOnError)
	c.register(fs, stderr, true)
	fs.BoolVar(&raw, "raw", false, "print Shodan's own document instead of this tool's projection")
	fs.BoolVar(&portsOnly, "ports-only", false, "attributes and the port list only")
	fs.Var(&ports, "port", "only this port's services (repeatable)")
	ips, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(ips) == 0 {
		fmt.Fprintln(stderr, "shodan-lookup: host takes one or more IP addresses")
		return exitError
	}
	if raw && (portsOnly || len(ports) > 0) {
		fmt.Fprintln(stderr, "shodan-lookup: --raw prints Shodan's whole document; it does not combine with --port or --ports-only")
		return exitError
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			fmt.Fprintf(stderr, "shodan-lookup: --port %d is not between 1 and 65535\n", p)
			return exitError
		}
	}
	eng, _, ok := c.setup(version, stderr)
	if !ok {
		return exitError
	}

	ctx := context.Background()
	code := exitOK
	for i, ip := range ips {
		if raw {
			body, _, err := eng.Raw(ctx, ip, c.refresh)
			if err != nil {
				code = worse(code, exitFor(err))
				reportError(stderr, ip, err)
				continue
			}
			var buf bytes.Buffer
			if err := json.Indent(&buf, body, "", "  "); err != nil {
				code = worse(code, exitUpstream)
				reportError(stderr, ip, err)
				continue
			}
			buf.WriteByte('\n')
			_, _ = stdout.Write(jsonForTerminal(buf.Bytes()))
			continue
		}
		h, err := eng.LookupHost(ctx, ip, c.refresh)
		if err != nil {
			code = worse(code, exitFor(err))
			if c.jsonOut {
				// One JSON document per IP, errors included: a stream, not an array.
				emitJSON(stdout, stderr, map[string]any{"ip": ip, "error": errorJSON(err)})
			} else if exitFor(err) == exitOK {
				fmt.Fprintln(stdout, visible(err.Error(), false))
			} else {
				reportError(stderr, ip, err)
			}
			continue
		}
		notObserved := filterPorts(h, ports, portsOnly)
		if c.jsonOut {
			out := struct {
				*engine.Host
				PortsNotObserved []int `json:"ports_not_observed,omitempty"`
			}{h, notObserved}
			code = worse(code, emitJSON(stdout, stderr, out))
			continue
		}
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		printHost(stdout, forText(h), notObserved, portsOnly)
	}
	return code
}

// filterPorts applies --port and --ports-only to a complete projection and
// returns the asked-for ports Shodan did not observe.
func filterPorts(h *engine.Host, ports []int, portsOnly bool) []int {
	if portsOnly {
		h.Services, h.Vulns = []engine.Service{}, []engine.Vuln{}
		return nil
	}
	if len(ports) == 0 {
		return nil
	}
	want := map[int]bool{}
	for _, p := range ports {
		want[p] = true
	}
	seen := map[int]bool{}
	kept := []engine.Service{}
	for _, s := range h.Services {
		if want[s.Port] {
			kept = append(kept, s)
			seen[s.Port] = true
		}
	}
	h.Services = kept
	var missing []int
	for p := range want {
		if !seen[p] {
			missing = append(missing, p)
		}
	}
	sort.Ints(missing)
	return missing
}

func printHost(w io.Writer, h *engine.Host, notObserved []int, portsOnly bool) {
	head := h.IP
	if h.Org != "" {
		head += "  " + h.Org
	}
	if h.ASN != "" {
		head += " (" + h.ASN + ")"
	}
	if loc := strings.TrimSpace(h.CountryCode + " " + h.City); loc != "" {
		head += "  " + loc
	}
	fmt.Fprintln(w, head)
	if h.ISP != "" && h.ISP != h.Org {
		fmt.Fprintf(w, "  isp:        %s\n", h.ISP)
	}
	if len(h.Hostnames) > 0 {
		fmt.Fprintf(w, "  hostnames:  %s\n", strings.Join(h.Hostnames, ", "))
	}
	if len(h.Domains) > 0 {
		fmt.Fprintf(w, "  domains:    %s\n", strings.Join(h.Domains, ", "))
	}
	if len(h.Tags) > 0 {
		fmt.Fprintf(w, "  tags:       %s\n", strings.Join(h.Tags, ", "))
	}
	if h.LastUpdate != "" {
		fmt.Fprintf(w, "  last seen:  %s\n", h.LastUpdate)
	}
	fmt.Fprintf(w, "  ports:      %s   (services: %d, inferred CVEs: %d)\n", intList(h.Ports), h.ServiceCount, h.VulnCount)
	if len(notObserved) > 0 {
		fmt.Fprintf(w, "  not observed by Shodan (not evidence that they are closed): %s\n", intList(notObserved))
	}
	if portsOnly {
		printProvenance(w, h.Provenance)
		return
	}

	for _, s := range h.Services {
		line := fmt.Sprintf("  %d/%s", s.Port, s.Transport)
		for _, part := range []string{s.Module, strings.TrimSpace(s.Product + " " + s.Version)} {
			if part != "" {
				line += "  " + part
			}
		}
		if s.Timestamp != "" {
			line += "  observed " + s.Timestamp
			if s.AgeHours != nil {
				line += fmt.Sprintf(" (%.1f h ago)", *s.AgeHours)
			}
		}
		fmt.Fprintln(w, line)
		if s.HTTP != nil {
			status := "-"
			if s.HTTP.Status != nil {
				status = fmt.Sprint(*s.HTTP.Status)
			}
			fmt.Fprintf(w, "      http: %s %q  server %s\n", status, clipLine(s.HTTP.Title, 80), orDash(s.HTTP.Server))
		}
		if s.SSL != nil {
			exp := ""
			if s.SSL.Expired != nil && *s.SSL.Expired {
				exp = "  EXPIRED as of " + s.SSL.ExpiredAsOf
			}
			fmt.Fprintf(w, "      tls:  CN=%s  issuer %s  valid %s .. %s%s\n", orDash(s.SSL.SubjectCN), orDash(s.SSL.IssuerCN),
				day(s.SSL.NotBefore), day(s.SSL.NotAfter), exp)
		}
		if first := firstLine(s.Banner); first != "" {
			more := ""
			if s.BannerChars > len([]rune(first)) {
				more = fmt.Sprintf("  (%d chars; `service %s %d --section banner`)", s.BannerChars, h.IP, s.Port)
			}
			fmt.Fprintf(w, "      banner: %s%s\n", clipLine(first, 100), more)
		}
	}
	if len(h.Vulns) > 0 {
		fmt.Fprintln(w, "  inferred CVEs, highest CVSS first (inferred from banner versions; not confirmed unless verified):")
		for _, v := range h.Vulns {
			ver := ""
			if v.Verified {
				ver = "  verified"
			}
			fmt.Fprintf(w, "    %-16s cvss %-4s epss %-6s ports %s%s\n", v.ID, num(v.CVSS, "%.1f"), num(v.EPSS, "%.3f"), intList(v.Ports), ver)
		}
	}
	printNotes(w, h.Notes)
	printProvenance(w, h.Provenance)
}

func intList(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprint(x)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func day(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return orDash(ts)
}

// firstLine is the first non-blank line of a banner — a DNS banner starts with
// an empty one.
func firstLine(banner string) string {
	for _, l := range strings.Split(banner, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			return t
		}
	}
	return ""
}
