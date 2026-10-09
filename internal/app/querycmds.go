package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/nlink-jp/shodan-lookup/internal/engine"
)

// servicePage is a section page in a form forText can reach into: the items
// of a page are typed here, not held as interfaces.
type servicePage struct {
	*engine.Page
	Lines []string             `json:"-"`
	Vulns []engine.SectionVuln `json:"-"`
}

func runService(args []string, version string, stdout, stderr io.Writer) int {
	var c common
	var transport, section string
	var offset, limit int
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	c.register(fs, stderr, true)
	fs.StringVar(&transport, "transport", "", "tcp or udp (required when the port has both)")
	fs.StringVar(&section, "section", "", "banner | http_html | http_headers | ssl_cert | ssl_chain | vulns")
	fs.IntVar(&offset, "offset", 0, "characters or items to skip")
	fs.IntVar(&limit, "limit", 0, "characters (default 4000) or items (default 50) to return")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(pos) != 2 || section == "" {
		fmt.Fprintln(stderr, "shodan-lookup: service takes <IP> <PORT> and --section "+strings.Join(engine.Sections, "|"))
		return exitError
	}
	port, perr := strconv.Atoi(pos[1])
	if perr != nil {
		fmt.Fprintf(stderr, "shodan-lookup: %q is not a port number\n", visible(pos[1], false))
		return exitError
	}
	if given(fs)["limit"] && limit == 0 {
		fmt.Fprintln(stderr, "shodan-lookup: --limit must be at least 1")
		return exitError
	}
	eng, _, ok := c.setup(version, stderr)
	if !ok {
		return exitError
	}
	p, err := eng.GetService(context.Background(), engine.ServiceQuery{IP: pos[0], Port: port, Transport: transport,
		Section: section, Offset: offset, Limit: limit}, c.refresh)
	if err != nil {
		if c.jsonOut {
			emitJSON(stdout, stderr, map[string]any{"ip": pos[0], "port": port, "error": errorJSON(err)})
		} else if exitFor(err) == exitOK {
			fmt.Fprintf(stdout, "%s %d\n  %s\n", visible(pos[0], false), port, visible(err.Error(), false))
		} else {
			reportError(stderr, pos[0], err)
		}
		return exitFor(err)
	}
	if c.jsonOut {
		return emitJSON(stdout, stderr, p)
	}

	view := &servicePage{Page: p}
	for _, it := range p.Items {
		switch v := it.(type) {
		case string:
			view.Lines = append(view.Lines, v)
		case engine.SectionVuln:
			view.Vulns = append(view.Vulns, v)
		}
	}
	view.Items = nil
	forText(view)

	fmt.Fprintf(stdout, "%s %d/%s  %s  (%d %s, from %d)\n", p.IP, p.Port, p.Transport, p.Section, p.Total, p.Unit, p.Offset)
	switch {
	case p.Text != "":
		block(stdout, view.Text)
	case len(view.Lines) > 0:
		for i, l := range view.Lines {
			fmt.Fprintf(stdout, "  [%d]\n", p.Offset+i)
			block(stdout, l)
		}
	case len(view.Vulns) > 0:
		for _, v := range view.Vulns {
			ver := ""
			if v.Verified {
				ver = "  verified"
			}
			fmt.Fprintf(stdout, "  %s  cvss %s  epss %s%s\n", v.ID, num(v.CVSS, "%.1f"), num(v.EPSS, "%.3f"), ver)
			if v.Summary != "" {
				block(stdout, v.Summary)
			}
			for _, r := range v.References {
				fmt.Fprintf(stdout, "      ref: %s\n", r)
			}
		}
	}
	if p.NextOffset != nil {
		fmt.Fprintf(stdout, "  more: --offset %d\n", *p.NextOffset)
	}
	printNotes(stdout, view.Notes)
	printProvenance(stdout, p.Provenance)
	return exitOK
}

func runCount(args []string, version string, stdout, stderr io.Writer) int {
	var c common
	var facets multiFlag
	fs := flag.NewFlagSet("count", flag.ContinueOnError)
	c.register(fs, stderr, true)
	fs.Var(&facets, "facet", "a breakdown, name or name:N (N 1-1000, default 10); repeatable")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(pos) == 0 {
		fmt.Fprintln(stderr, "shodan-lookup: count takes a Shodan query, e.g. 'port:3389 country:JP'")
		return exitError
	}
	query := strings.Join(pos, " ")
	specs := make([]engine.FacetSpec, 0, len(facets))
	for _, f := range facets {
		spec, err := engine.ParseFacet(f)
		if err != nil {
			reportError(stderr, "", err)
			return exitError
		}
		specs = append(specs, spec)
	}
	eng, _, ok := c.setup(version, stderr)
	if !ok {
		return exitError
	}
	res, err := eng.CountServices(context.Background(), query, specs, c.refresh)
	if err != nil {
		if c.jsonOut {
			emitJSON(stdout, stderr, map[string]any{"query": query, "error": errorJSON(err)})
		} else {
			reportError(stderr, "", err)
		}
		return exitFor(err)
	}
	if c.jsonOut {
		return emitJSON(stdout, stderr, res)
	}
	forText(res)
	fmt.Fprintf(stdout, "%s\n  %d matching %s\n", res.Query, res.Total, res.Unit)
	for _, f := range res.Facets {
		fmt.Fprintf(stdout, "  %s (top %d):\n", f.Name, f.Requested)
		if len(f.Values) == 0 {
			fmt.Fprintln(stdout, "    -")
		}
		for _, v := range f.Values {
			fmt.Fprintf(stdout, "    %8d  %s\n", v.Count, v.Value)
		}
	}
	printNotes(stdout, res.Notes)
	printProvenance(stdout, res.Provenance)
	return exitOK
}

func runQuota(args []string, version string, stdout, stderr io.Writer) int {
	var c common
	fs := flag.NewFlagSet("quota", flag.ContinueOnError)
	c.register(fs, stderr, false)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(pos) > 0 {
		fmt.Fprintf(stderr, "shodan-lookup: quota takes no arguments (got %q)\n", visible(pos[0], false))
		return exitError
	}
	eng, _, ok := c.setup(version, stderr)
	if !ok {
		return exitError
	}
	q, err := eng.GetQuota(context.Background())
	if err != nil {
		if c.jsonOut {
			emitJSON(stdout, stderr, map[string]any{"error": errorJSON(err)})
		} else {
			reportError(stderr, "", err)
		}
		return exitFor(err)
	}
	if c.jsonOut {
		return emitJSON(stdout, stderr, q)
	}
	forText(q)
	plan := q.Plan
	if q.PlanName != "" {
		plan += " (" + q.PlanName + ")"
	}
	fmt.Fprintf(stdout, "plan:           %s\n", plan)
	fmt.Fprintf(stdout, "query credits:  %d of %d\n", q.QueryCredits, q.Limits.QueryCredits)
	fmt.Fprintf(stdout, "scan credits:   %d of %d (never used by this tool)\n", q.ScanCredits, q.Limits.ScanCredits)
	fmt.Fprintf(stdout, "monitored IPs:  %d of %d\n", q.MonitoredIPs, q.Limits.MonitoredIPs)
	fmt.Fprintf(stdout, "read:           %s (live)\n", q.FetchedAt)
	printNotes(stdout, q.Notes)
	return exitOK
}
