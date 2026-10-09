package app

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/nlink-jp/shodan-lookup/internal/engine"
)

func runTokens(args []string, version string, stdout, stderr io.Writer) int {
	var c common
	fs := flag.NewFlagSet("tokens", flag.ContinueOnError)
	c.register(fs, stderr, false)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(pos) == 0 {
		fmt.Fprintln(stderr, "shodan-lookup: tokens takes a Shodan query")
		return exitError
	}
	query := strings.Join(pos, " ")
	eng, _, ok := c.setup(version, stderr)
	if !ok {
		return exitError
	}
	r, err := eng.ParseQuery(context.Background(), query)
	if err != nil {
		if c.jsonOut {
			emitJSON(stdout, stderr, map[string]any{"query": query, "error": errorJSON(err)})
		} else {
			reportError(stderr, "", err)
		}
		return exitFor(err)
	}
	if c.jsonOut {
		return emitJSON(stdout, stderr, r)
	}
	forText(r)
	fmt.Fprintln(stdout, r.Query)
	fmt.Fprintf(stdout, "  filters:    %s\n", orDash(strings.Join(r.Filters, ", ")))
	fmt.Fprintf(stdout, "  free text:  %s\n", orDash(r.FreeText))
	if len(r.Errors) > 0 {
		fmt.Fprintf(stdout, "  errors:     %s\n", strings.Join(r.Errors, "; "))
	}
	fmt.Fprintf(stdout, "  a search would spend %d credit(s) for page 1, and 1 for any later page\n", r.PredictedCost)
	printNotes(stdout, r.Notes)
	return exitOK
}

func runSearch(args []string, version string, stdout, stderr io.Writer) int {
	var c common
	var facets multiFlag
	var page int
	var raw bool
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	c.register(fs, stderr, true)
	fs.Var(&facets, "facet", "a breakdown, name or name:N (N 1-1000, default 10); repeatable")
	fs.IntVar(&page, "page", 1, "page 1-10, 100 results each")
	fs.BoolVar(&raw, "raw", false, "print Shodan's own page: every banner in full")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(pos) == 0 {
		fmt.Fprintln(stderr, "shodan-lookup: search takes a Shodan query, e.g. 'product:nginx country:JP'")
		return exitError
	}
	if raw && c.jsonOut {
		fmt.Fprintln(stderr, "shodan-lookup: --raw and --json do not combine")
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
	res, err := eng.SearchServices(context.Background(), engine.SearchQuery{Query: query, Facets: specs, Page: page}, c.refresh)
	if err != nil {
		if c.jsonOut {
			emitJSON(stdout, stderr, map[string]any{"query": query, "error": errorJSON(err)})
		} else {
			reportError(stderr, "", err)
		}
		return exitFor(err)
	}
	// What was spent goes to stderr whatever the format, so it is seen even
	// when stdout is piped.
	printCredits(stderr, res.Credits, res.Provenance.Cached)
	switch {
	case raw:
		var buf bytes.Buffer
		if err := json.Indent(&buf, res.Raw(), "", "  "); err != nil {
			reportError(stderr, "", err)
			return exitUpstream
		}
		buf.WriteByte('\n')
		_, _ = stdout.Write(jsonForTerminal(buf.Bytes()))
		return exitOK
	case c.jsonOut:
		return emitJSON(stdout, stderr, res)
	}
	forText(res)
	fmt.Fprintf(stdout, "%s  (page %d)\n  %d matching %s\n", res.Query, res.Page, res.Total, res.Unit)
	for _, r := range res.Rows {
		line := fmt.Sprintf("  %-39s %5d/%s", r.IP, r.Port, r.Transport)
		for _, part := range []string{strings.TrimSpace(r.Product + " " + r.Version), r.Org, r.CountryCode} {
			if part != "" {
				line += "  " + part
			}
		}
		if r.Title != "" {
			line += fmt.Sprintf("  %q", clipLine(r.Title, 50))
		}
		if r.VulnCount > 0 {
			line += fmt.Sprintf("  (%d CVEs inferred)", r.VulnCount)
		}
		fmt.Fprintln(stdout, line)
	}
	for _, f := range res.Facets {
		fmt.Fprintf(stdout, "  %s (top %d):\n", f.Name, f.Requested)
		for _, v := range f.Values {
			fmt.Fprintf(stdout, "    %8d  %s\n", v.Count, v.Value)
		}
	}
	printNotes(stdout, res.Notes)
	printProvenance(stdout, res.Provenance)
	return exitOK
}

func printCredits(w io.Writer, c *engine.Credits, cached bool) {
	switch {
	case cached:
		fmt.Fprintln(w, "shodan-lookup: from the local cache — no query credit was spent")
	case c == nil:
	case c.Spent == nil:
		fmt.Fprintf(w, "shodan-lookup: credits before %d; what this search spent could not be read — searching is stopped for this process\n", c.Before)
	default:
		fmt.Fprintf(w, "shodan-lookup: spent %d query credit(s) (predicted %d): %d → %d, floor %d\n", *c.Spent, c.Predicted, c.Before, *c.After, c.Floor)
	}
}
