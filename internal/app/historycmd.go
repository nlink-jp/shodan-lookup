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

func runHistory(args []string, version string, stdout, stderr io.Writer) int {
	var c common
	var raw bool
	var transport string
	var port, offset, limit int
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	c.register(fs, stderr, true)
	fs.BoolVar(&raw, "raw", false, "print Shodan's own history document: every banner in full")
	fs.IntVar(&port, "port", 0, "also list this port's observations, newest first")
	fs.StringVar(&transport, "transport", "", "tcp or udp (required when the port has history on both)")
	fs.IntVar(&offset, "offset", 0, "observations to skip")
	fs.IntVar(&limit, "limit", 0, "observations to return (default 50)")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "shodan-lookup: history takes one IP address")
		return exitError
	}
	set := given(fs)
	if (set["transport"] || set["offset"] || set["limit"]) && !set["port"] {
		fmt.Fprintln(stderr, "shodan-lookup: --transport, --offset and --limit apply to one port's observations; pass --port")
		return exitError
	}
	if set["limit"] && limit == 0 {
		fmt.Fprintln(stderr, "shodan-lookup: --limit must be at least 1")
		return exitError
	}
	if set["port"] && port == 0 {
		fmt.Fprintln(stderr, "shodan-lookup: --port must be between 1 and 65535")
		return exitError
	}
	if raw && set["port"] {
		fmt.Fprintln(stderr, "shodan-lookup: --raw prints Shodan's whole history; it does not combine with --port")
		return exitError
	}
	eng, _, ok := c.setup(version, stderr)
	if !ok {
		return exitError
	}
	ctx := context.Background()
	ip := pos[0]

	if raw {
		body, err := eng.RawHistory(ctx, ip, c.refresh)
		if err != nil {
			reportError(stderr, ip, err)
			return exitFor(err)
		}
		var buf bytes.Buffer
		if err := json.Indent(&buf, body, "", "  "); err != nil {
			reportError(stderr, ip, err)
			return exitUpstream
		}
		buf.WriteByte('\n')
		_, _ = stdout.Write(jsonForTerminal(buf.Bytes()))
		return exitOK
	}

	h, err := eng.GetHistory(ctx, engine.HistoryQuery{IP: ip, Port: port, Transport: transport, Offset: offset, Limit: limit}, c.refresh)
	if err != nil {
		if c.jsonOut {
			emitJSON(stdout, stderr, map[string]any{"ip": ip, "error": errorJSON(err)})
		} else if exitFor(err) == exitOK {
			fmt.Fprintln(stdout, visible(err.Error(), false))
		} else {
			reportError(stderr, ip, err)
		}
		return exitFor(err)
	}
	if c.jsonOut {
		return emitJSON(stdout, stderr, h)
	}
	printHistory(stdout, forText(h))
	return exitOK
}

func printHistory(w io.Writer, h *engine.History) {
	win := h.Window
	capped := ""
	if win.Capped {
		capped = fmt.Sprintf(" — Shodan's cap of %d; nothing earlier can be read", win.Cap)
	}
	fmt.Fprintf(w, "%s  history %s .. %s  (%d banners%s)\n", h.IP, orDash(win.Oldest), orDash(win.Newest), win.Banners, capped)
	for _, p := range h.Ports {
		fmt.Fprintf(w, "  %d/%s  seen %s .. %s  (%d observations, %d variant%s)\n", p.Port, p.Transport,
			p.FirstSeen, p.LastSeen, p.Observations, p.VariantCount, plural(p.VariantCount, "", "s"))
		for _, v := range p.Variants {
			var parts []string
			if pv := strings.TrimSpace(v.Product + " " + v.Version); pv != "" {
				parts = append(parts, pv)
			}
			if v.Title != "" {
				parts = append(parts, fmt.Sprintf("%q", clipLine(v.Title, 60)))
			}
			if v.CertSHA1 != "" {
				parts = append(parts, "cert "+v.CertSHA1)
			}
			if len(parts) == 0 {
				parts = append(parts, "(no product, title or certificate)")
			}
			fmt.Fprintf(w, "      %s .. %s  ×%d  %s\n", v.FirstSeen, v.LastSeen, v.Observations, strings.Join(parts, "  "))
		}
	}
	if p := h.Port; p != nil {
		fmt.Fprintf(w, "  %d/%s observations, newest first (%d, from %d):\n", p.Port, p.Transport, p.Total, p.Offset)
		for _, o := range p.Items {
			fmt.Fprintf(w, "    %s  %s  (%d chars)\n", o.Timestamp, clipLine(o.FirstLine, 100), o.BannerChars)
		}
		if p.NextOffset != nil {
			fmt.Fprintf(w, "  more: --offset %d\n", *p.NextOffset)
		}
	}
	printNotes(w, h.Notes)
	printProvenance(w, h.Provenance)
}
