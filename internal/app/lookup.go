package app

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/config"
	"github.com/nlink-jp/shodan-lookup/internal/engine"
	"github.com/nlink-jp/shodan-lookup/internal/shodan"
	"github.com/nlink-jp/shodan-lookup/internal/termsafe"
)

// common holds the flags every lookup command shares.
type common struct {
	jsonOut    bool
	configPath string
	timeout    float64
	refresh    bool
	fs         *flag.FlagSet
}

// given reports which flags the operator actually passed. Whether a flag was
// given is asked of the flag set and never guessed from its value.
func given(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

func (c *common) register(fs *flag.FlagSet, stderr io.Writer, withRefresh bool) {
	c.fs = fs
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	fs.BoolVar(&c.jsonOut, "json", false, "JSON output (complete)")
	fs.BoolVar(&c.jsonOut, "j", false, "JSON output (shorthand)")
	fs.StringVar(&c.configPath, "config", "", "config file path")
	fs.StringVar(&c.configPath, "c", "", "config file path (shorthand)")
	fs.Float64Var(&c.timeout, "timeout", 0, "network timeout in seconds (overrides the config)")
	if withRefresh {
		fs.BoolVar(&c.refresh, "refresh", false, "bypass the cache and fetch again")
	}
}

// UserAgent identifies this tool to Shodan, honestly and with a way to reach
// its maintainers.
func UserAgent(version string) string {
	return "shodan-lookup/" + version + " (+https://github.com/nlink-jp/shodan-lookup)"
}

// NewEngine wires the shared core from configuration. The MCP server builds
// its engine through here too, so the two faces cannot be wired differently.
func NewEngine(cfg *config.Config, version string) *engine.Engine {
	client := shodan.New(cfg.BaseURL, cfg.APIKey, cfg.Timeout, cfg.MinInterval, UserAgent(version))
	return engine.New(cfg, client, &cache.Store{Dir: cfg.CacheDir})
}

// setup loads the configuration and builds the engine. ok is false when the
// command should stop with exitError; the reason has been written to stderr.
func (c *common) setup(version string, stderr io.Writer) (eng *engine.Engine, cfg *config.Config, ok bool) {
	var timeout time.Duration
	if c.fs != nil && given(c.fs)["timeout"] {
		d, err := config.TimeoutSeconds(c.timeout)
		if err != nil {
			fmt.Fprintf(stderr, "shodan-lookup: --timeout: %v\n", err)
			return nil, nil, false
		}
		timeout = d
	}
	cfg, err := config.Load(c.configPath, timeout)
	if err != nil {
		fmt.Fprintf(stderr, "shodan-lookup: %v\n", err)
		return nil, nil, false
	}
	return NewEngine(cfg, version), cfg, true
}

// exitFor maps a lookup error onto the exit contract. A refused input and a
// missing or refused key are usage / configuration errors. not_indexed and
// not_observed are answers, so they do not fail the run. Everything else
// means upstream could not be asked, or not fully.
func exitFor(err error) int {
	switch engine.Code(err) {
	case engine.CodeInvalidArgument, engine.CodePlanRestricted, shodan.CodeMissingKey, shodan.CodeAuthFailed:
		return exitError
	case engine.CodeNotIndexed, engine.CodeNotObserved:
		return exitOK
	default:
		return exitUpstream
	}
}

// worse keeps the more serious of two exit codes: a usage error outranks an
// upstream failure, which outranks success.
func worse(a, b int) int {
	rank := map[int]int{exitOK: 0, exitUpstream: 1, exitError: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func errorJSON(err error) errorBody {
	code := engine.Code(err)
	if code == "" {
		code = "internal_error"
	}
	return errorBody{Code: code, Message: err.Error()}
}

// reportError writes a lookup failure to stderr, made inert: the message can
// carry upstream's text.
func reportError(stderr io.Writer, target string, err error) {
	code := engine.Code(err)
	if code == "" {
		code = "internal_error"
	}
	prefix := "shodan-lookup: "
	if target != "" {
		prefix += visible(target, false) + ": "
	}
	fmt.Fprintf(stderr, "%s%s (%s)\n", prefix, visible(err.Error(), false), code)
}

func emitJSON(w io.Writer, stderr io.Writer, v any) int {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(stderr, "shodan-lookup: encode output: %v\n", err)
		return exitError
	}
	// --json is typed at a terminal as often as it is piped.
	if _, err := w.Write(jsonForTerminal(buf.Bytes())); err != nil {
		fmt.Fprintf(stderr, "shodan-lookup: write output: %v\n", err)
		return exitError
	}
	return exitOK
}

// visible makes third-party text safe to print on a terminal: control
// characters (C0, DEL, C1) and the Unicode bidirectional controls are shown as
// escapes instead of being obeyed. Newlines and tabs survive only when
// multiline is true, and the caller indents continuation lines so that an
// embedded newline cannot forge a line of this tool's own output.
func visible(s string, multiline bool) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case multiline && (r == '\n' || r == '\t'):
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\x%02x", r)
		case termsafe.Obeyed(r):
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// block prints third-party multi-line text with every line behind a gutter.
// A banner's CRLF line ends are shown as line ends, not as \x0d.
func block(w io.Writer, text string) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	for _, line := range strings.Split(visible(strings.TrimRight(text, "\n"), true), "\n") {
		fmt.Fprintf(w, "    | %s\n", strings.TrimRight(line, " \t"))
	}
}

// clipLine shortens third-party text for a one-line listing.
func clipLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "…"
	}
	return visible(s, false)
}

func num(f *float64, format string) string {
	if f == nil {
		return "-"
	}
	return fmt.Sprintf(format, *f)
}

func printNotes(w io.Writer, notes []string) {
	for _, n := range notes {
		fmt.Fprintf(w, "  note: %s\n", visible(n, false))
	}
}

func printProvenance(w io.Writer, p engine.Provenance) {
	cached := ""
	if p.Cached {
		cached = " (cached — --refresh fetches again)"
	}
	fmt.Fprintf(w, "  source: Shodan %s, fetched %s%s\n", visible(p.Endpoint, false), p.FetchedAt, cached)
}

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// multiInt is a repeatable integer flag.
type multiInt []int

func (m *multiInt) String() string { return fmt.Sprint([]int(*m)) }
func (m *multiInt) Set(v string) error {
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || fmt.Sprint(n) != strings.TrimSpace(v) {
		return fmt.Errorf("%q is not an integer", v)
	}
	*m = append(*m, n)
	return nil
}
