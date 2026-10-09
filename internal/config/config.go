package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the root of the Shodan REST API.
	DefaultBaseURL = "https://api.shodan.io"
	// DefaultServices is how many services a host lookup lists before the
	// rest are counted. One measured host had 16; the cap is for the hosts
	// that have hundreds.
	DefaultServices = 50
	// DefaultVulns is how many inferred CVEs a host lookup lists, highest
	// CVSS first, before the rest are counted. One measured host had 138.
	DefaultVulns = 25
	// DefaultBannerBytes caps each service's banner in the compact answer,
	// counted after escaping: a banner of control characters grows sixfold
	// in JSON, and fifty of them must not push a result over the server's
	// ceiling.
	DefaultBannerBytes = 512
	// DefaultCreditFloor is how many query credits a search must leave
	// untouched. Membership grants 100 a month; the floor keeps a share for
	// the operator's own hands however many searches an agent attempts.
	DefaultCreditFloor = 20
	// DefaultHostTTL is how long a cached host record stays fresh. Shodan
	// re-crawls continuously; half a day keeps an investigation to one
	// request per IP, and refresh is always available.
	DefaultHostTTL = 12 * time.Hour
	// DefaultCountTTL is how long a cached count or facet breakdown stays
	// fresh. Counts move with every crawl.
	DefaultCountTTL = 1 * time.Hour
	// DefaultSearchTTL is how long a cached search page stays fresh. It is
	// long on purpose: a filtered search costs a query credit, and the same
	// question must not spend a second one.
	DefaultSearchTTL = 24 * time.Hour
	// DefaultTimeout bounds each HTTPS exchange.
	DefaultTimeout = 30 * time.Second
	// DocumentedMinInterval is Shodan's documented rate: one request per
	// second, on every plan.
	DocumentedMinInterval = time.Second
	// DefaultMinInterval is this process's pacing, deliberately half the
	// documented rate. The limit is per key and the pacing is per process: a
	// CLI loop and the MCP servers of several agent runtimes spend from one
	// key, and none of them can see what the others have spent.
	DefaultMinInterval = 2 * time.Second

	// Ranges. Each exists so that a value is refused by name instead of
	// being interpreted — a 1e300-hour TTL would overflow a time.Duration
	// into something negative.
	maxServices       = 500
	maxVulns          = 500
	minBannerBytes    = 64
	maxBannerBytes    = 16 << 10
	maxCreditFloor    = 1_000_000
	maxTTLHours       = 366 * 24
	maxTimeoutSeconds = 3600
	maxIntervalMillis = 600_000
)

// Config holds resolved runtime settings.
type Config struct {
	Path            string        // config file actually read; "" when none was
	APIKey          string        // Shodan API key; never rendered (see Redacted)
	BaseURL         string        // API root; operator configuration only
	DefaultServices int           // services listed before the rest are counted
	DefaultVulns    int           // inferred CVEs listed before the rest are counted
	BannerBytes     int           // per-service banner cap, after escaping
	CreditFloor     int           // query credits a search must leave untouched
	CacheDir        string        // result-cache directory
	HostTTL         time.Duration // freshness window for host records; 0 = not cached
	CountTTL        time.Duration // freshness window for counts; 0 = not cached
	SearchTTL       time.Duration // freshness window for search pages; 0 = not cached
	Timeout         time.Duration // network timeout per exchange
	MinInterval     time.Duration // client-side pacing between requests
}

// HasKey reports whether an API key is configured.
func (c *Config) HasKey() bool { return c.APIKey != "" }

// Redacted returns the config with the key replaced by a fixed marker, for
// anything that prints or serialises settings. The key carries the operator's
// account authority, and every query made with it is recorded against that
// account.
func (c *Config) Redacted() Config {
	clone := *c
	if clone.APIKey != "" {
		clone.APIKey = "[set]"
	}
	return clone
}

// Load resolves configuration. If configPath is empty the first existing file
// among SearchPaths is used. Environment variables override file values; a
// non-zero timeoutOverride wins over both.
//
// No config file at all is not an error: everything but the key has a
// default, and the key may arrive through the environment. A path the caller
// named explicitly is different — if it does not exist, that is a mistake
// worth reporting rather than a reason to fall back to the defaults.
func Load(configPath string, timeoutOverride time.Duration) (*Config, error) {
	cfg := &Config{
		BaseURL:         DefaultBaseURL,
		DefaultServices: DefaultServices,
		DefaultVulns:    DefaultVulns,
		BannerBytes:     DefaultBannerBytes,
		CreditFloor:     DefaultCreditFloor,
		CacheDir:        DefaultCacheDir(),
		HostTTL:         DefaultHostTTL,
		CountTTL:        DefaultCountTTL,
		SearchTTL:       DefaultSearchTTL,
		Timeout:         DefaultTimeout,
		MinInterval:     DefaultMinInterval,
	}

	explicit := configPath != ""
	if !explicit {
		configPath = FindConfig()
	}
	if configPath != "" {
		f, err := os.Open(configPath)
		switch {
		case err == nil:
			sections, perr := parseTOML(f)
			_ = f.Close()
			if perr != nil {
				return nil, fmt.Errorf("parse config %s: %w", configPath, perr)
			}
			if aerr := applySections(cfg, sections); aerr != nil {
				return nil, fmt.Errorf("config %s: %w", configPath, aerr)
			}
			cfg.Path = configPath
		case os.IsNotExist(err) && !explicit:
			// Found by FindConfig and gone a moment later: same as not found.
		default:
			return nil, fmt.Errorf("open config %s: %w", configPath, err)
		}
	}

	if err := applyEnv(cfg); err != nil {
		return nil, err
	}
	if timeoutOverride > 0 {
		cfg.Timeout = timeoutOverride
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return cfg, validate(cfg)
}

func validate(cfg *Config) error {
	if strings.TrimSpace(cfg.CacheDir) == "" {
		return fmt.Errorf("[cache] dir must not be empty")
	}
	return validateBaseURL(cfg.BaseURL)
}

// validateBaseURL keeps base_url to what it is for: naming the host that
// serves the API. Every request — and with it the API key, which travels in
// the query string — goes there, so the key must never ride a plaintext
// channel: https only, with plain http allowed on loopback for tests.
// Credentials, a query and a fragment are refused outright; a URL is the one
// place a secret would end up in logs and error messages.
func validateBaseURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("[api] base_url must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Error quotes the whole input, which is exactly where a
		// mistakenly embedded credential would sit. Report the reason only.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("[api] base_url is not a valid URL: %v", err)
	}
	if u.Host == "" {
		return fmt.Errorf("[api] base_url has no host")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return fmt.Errorf("[api] base_url must be https: the API key travels in every request's query string (plain http is allowed only on loopback, for tests)")
		}
	default:
		return fmt.Errorf("[api] base_url must be an https URL, got scheme %q", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("[api] base_url must not carry credentials")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("[api] base_url must not carry a query or a fragment")
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// knownKeys is every section and key the file may hold. A key that is not here
// is refused rather than ignored: a misspelt setting that silently keeps its
// default is indistinguishable, from the outside, from one that was applied.
var knownKeys = map[string]map[string]bool{
	"api":     {"key": true, "base_url": true},
	"query":   {"default_services": true, "default_vulns": true, "banner_bytes": true},
	"search":  {"credit_floor": true},
	"cache":   {"host_ttl_hours": true, "count_ttl_hours": true, "search_ttl_hours": true, "dir": true},
	"network": {"timeout_seconds": true},
	"limits":  {"min_interval_ms": true},
}

func applySections(cfg *Config, sections map[string]map[string]string) error {
	if top := sections[""]; len(top) > 0 {
		return topLevelError(top)
	}
	for sec, kv := range sections {
		if sec == "" {
			continue
		}
		known, ok := knownKeys[sec]
		if !ok {
			return fmt.Errorf("unknown section [%s]", sec)
		}
		for k := range kv {
			if !known[k] {
				return fmt.Errorf("unknown key [%s] %s", sec, k)
			}
		}
	}

	// A key that is present was given, "" included: `key = ""` is a value to
	// refuse, not a line to skip. (Only an environment variable reads "" as
	// unset — that is what clearing one looks like.)
	if a := sections["api"]; a != nil {
		if v, ok := a["key"]; ok {
			if v == "" {
				return fmt.Errorf("[api] key is present but empty; remove the line or set the key")
			}
			cfg.APIKey = v
		}
		if v, ok := a["base_url"]; ok {
			if v == "" {
				return fmt.Errorf("[api] base_url is present but empty")
			}
			cfg.BaseURL = v
		}
	}
	for _, n := range []struct {
		sec, key string
		dst      *int
		min, max int
	}{
		{"query", "default_services", &cfg.DefaultServices, 1, maxServices},
		{"query", "default_vulns", &cfg.DefaultVulns, 1, maxVulns},
		{"query", "banner_bytes", &cfg.BannerBytes, minBannerBytes, maxBannerBytes},
		{"search", "credit_floor", &cfg.CreditFloor, 0, maxCreditFloor},
	} {
		if v, ok := sections[n.sec][n.key]; ok {
			i, err := parseIntIn(v, n.min, n.max)
			if err != nil {
				return fmt.Errorf("[%s] %s: %w", n.sec, n.key, err)
			}
			*n.dst = i
		}
	}
	if c := sections["cache"]; c != nil {
		for _, t := range []struct {
			key string
			dst *time.Duration
		}{
			{"host_ttl_hours", &cfg.HostTTL},
			{"count_ttl_hours", &cfg.CountTTL},
			{"search_ttl_hours", &cfg.SearchTTL},
		} {
			if v, ok := c[t.key]; ok {
				d, err := parseTTLHours(v)
				if err != nil {
					return fmt.Errorf("[cache] %s: %w", t.key, err)
				}
				*t.dst = d
			}
		}
		if v, ok := c["dir"]; ok {
			if v == "" {
				return fmt.Errorf("[cache] dir is present but empty")
			}
			cfg.CacheDir = expandHome(v)
		}
	}
	if v, ok := sections["network"]["timeout_seconds"]; ok {
		d, err := parseSeconds(v)
		if err != nil {
			return fmt.Errorf("[network] timeout_seconds: %w", err)
		}
		cfg.Timeout = d
	}
	if v, ok := sections["limits"]["min_interval_ms"]; ok {
		d, err := parseMillis(v)
		if err != nil {
			return fmt.Errorf("[limits] min_interval_ms: %w", err)
		}
		cfg.MinInterval = d
	}
	return nil
}

// topLevelError explains a key written outside any section. The common case
// is the shape other Shodan tooling uses, `api_key = "..."` on its own line,
// so that one is named with where it belongs.
func topLevelError(top map[string]string) error {
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "api_key" || k == "key" {
			return fmt.Errorf("%s is outside any [section]; write it as `key = \"...\"` under [api]", k)
		}
	}
	return fmt.Errorf("keys outside a [section] are not allowed: %s", strings.Join(keys, ", "))
}

func applyEnv(cfg *Config) error {
	// SHODAN_LOOKUP_API_KEY is this tool's own name and wins. SHODAN_API_KEY
	// is a name Shodan users commonly export, accepted so an environment
	// already set up for it works here unchanged.
	if v := os.Getenv("SHODAN_LOOKUP_API_KEY"); v != "" {
		cfg.APIKey = v
	} else if v := os.Getenv("SHODAN_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("SHODAN_LOOKUP_BASE_URL"); v != "" {
		cfg.BaseURL = v
	}
	if v := os.Getenv("SHODAN_LOOKUP_CACHE_DIR"); v != "" {
		cfg.CacheDir = expandHome(v)
	}
	for _, n := range []struct {
		name     string
		dst      *int
		min, max int
	}{
		{"SHODAN_LOOKUP_DEFAULT_SERVICES", &cfg.DefaultServices, 1, maxServices},
		{"SHODAN_LOOKUP_DEFAULT_VULNS", &cfg.DefaultVulns, 1, maxVulns},
		{"SHODAN_LOOKUP_BANNER_BYTES", &cfg.BannerBytes, minBannerBytes, maxBannerBytes},
		{"SHODAN_LOOKUP_CREDIT_FLOOR", &cfg.CreditFloor, 0, maxCreditFloor},
	} {
		if v := os.Getenv(n.name); v != "" {
			i, err := parseIntIn(v, n.min, n.max)
			if err != nil {
				return fmt.Errorf("%s: %w", n.name, err)
			}
			*n.dst = i
		}
	}
	for _, t := range []struct {
		name string
		dst  *time.Duration
	}{
		{"SHODAN_LOOKUP_HOST_TTL_HOURS", &cfg.HostTTL},
		{"SHODAN_LOOKUP_COUNT_TTL_HOURS", &cfg.CountTTL},
		{"SHODAN_LOOKUP_SEARCH_TTL_HOURS", &cfg.SearchTTL},
	} {
		if v := os.Getenv(t.name); v != "" {
			d, err := parseTTLHours(v)
			if err != nil {
				return fmt.Errorf("%s: %w", t.name, err)
			}
			*t.dst = d
		}
	}
	if v := os.Getenv("SHODAN_LOOKUP_TIMEOUT_SECONDS"); v != "" {
		d, err := parseSeconds(v)
		if err != nil {
			return fmt.Errorf("SHODAN_LOOKUP_TIMEOUT_SECONDS: %w", err)
		}
		cfg.Timeout = d
	}
	if v := os.Getenv("SHODAN_LOOKUP_MIN_INTERVAL_MS"); v != "" {
		d, err := parseMillis(v)
		if err != nil {
			return fmt.Errorf("SHODAN_LOOKUP_MIN_INTERVAL_MS: %w", err)
		}
		cfg.MinInterval = d
	}
	return nil
}

// parseIntIn accepts an integer in [min, max].
func parseIntIn(v string, min, max int) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%q is not an integer from %d to %d", v, min, max)
	}
	return n, nil
}

// TimeoutSeconds is the same rule for a timeout that arrives as a number
// rather than as config text (the --timeout flag): above 0, at most an hour,
// and — because the range is stated from the inside — never NaN or Inf.
func TimeoutSeconds(s float64) (time.Duration, error) {
	if !(s > 0 && s <= maxTimeoutSeconds) {
		return 0, fmt.Errorf("%g is not a number above 0 and at most %d", s, maxTimeoutSeconds)
	}
	return wholeDuration(s, time.Second)
}

// wholeDuration turns a checked positive number of units into a Duration, and
// refuses one so small that it truncates to zero: 1e-10 seconds is above 0 and
// is no nanoseconds. A zero Duration does not mean "very short" to anything
// that receives it — Load reads a zero timeout as "no override" and net/http
// as "no timeout at all", so the smallest value anyone could write would
// become the largest.
func wholeDuration(n float64, unit time.Duration) (time.Duration, error) {
	d := time.Duration(n * float64(unit))
	if d <= 0 {
		return 0, fmt.Errorf("%g is too small to be a duration", n)
	}
	return d, nil
}

func parseSeconds(v string) (time.Duration, error) {
	s, err := parseFloatIn(v, false, maxTimeoutSeconds)
	if err != nil {
		return 0, err
	}
	return wholeDuration(s, time.Second)
}

func parseMillis(v string) (time.Duration, error) {
	ms, err := parseFloatIn(v, false, maxIntervalMillis)
	if err != nil {
		return 0, err
	}
	return wholeDuration(ms, time.Millisecond)
}

// parseTTLHours accepts 0 — "do not cache this kind" — or a positive number of
// hours up to a year. Zero is a stated choice here, unlike a timeout's: the
// terms of an upstream can forbid caching, and turning a cache off must not
// need a code change.
func parseTTLHours(v string) (time.Duration, error) {
	h, err := parseFloatIn(v, true, maxTTLHours)
	if err != nil {
		return 0, err
	}
	if h == 0 {
		return 0, nil
	}
	return wholeDuration(h, time.Hour)
}

// parseFloatIn accepts a number in (0, max], or [0, max] when zeroOK.
// ParseFloat also reads "NaN" and "Inf", and NaN passes every comparison
// written as `x <= 0`: the range is stated from the inside so that it cannot.
func parseFloatIn(v string, zeroOK bool, max float64) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	inRange := (f > 0 || (zeroOK && f == 0)) && f <= max && !math.IsNaN(f)
	if err != nil || !inRange {
		lower := "above 0"
		if zeroOK {
			lower = "0 or more"
		}
		return 0, fmt.Errorf("%q is not a number %s and at most %g", v, lower, max)
	}
	return f, nil
}

// SearchPaths lists where a config file is looked for, in order. macOS
// operators expect ~/.config too, so it is searched before Application
// Support rather than instead of it — and it is searched even when
// XDG_CONFIG_HOME is set, because a file that exists and is silently not read
// is worse than no file at all.
func SearchPaths() []string {
	var paths []string
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		paths = append(paths, filepath.Join(x, "shodan-lookup", "config.toml"))
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return paths
	}
	paths = append(paths, filepath.Join(home, ".config", "shodan-lookup", "config.toml"))
	if runtime.GOOS == "darwin" {
		paths = append(paths, filepath.Join(home, "Library", "Application Support", "shodan-lookup", "config.toml"))
	}
	return paths
}

// FindConfig returns the first existing search path, or "" when none exists.
func FindConfig() string {
	for _, p := range SearchPaths() {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// DefaultCacheDir returns the default cache directory, honoring
// XDG_CACHE_HOME. Cached answers are re-fetchable transient state, so they
// belong under the cache home, not data.
func DefaultCacheDir() string {
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "shodan-lookup")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "shodan-lookup-cache"
	}
	return filepath.Join(home, ".cache", "shodan-lookup")
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// parseTOML parses the minimal subset this tool needs: [section] headers and
// key = value lines, where value is an optionally quoted string. Comments start
// with '#'. It intentionally does not support arrays, nested tables, or typed
// values. Vendored from the sibling lookup tools rather than imported, matching
// the series.
func parseTOML(r io.Reader) (map[string]map[string]string, error) {
	sections := map[string]map[string]string{}
	current := ""
	sections[current] = map[string]string{}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if strings.HasPrefix(raw, "[") {
			end := strings.IndexByte(raw, ']')
			if end < 0 {
				return nil, fmt.Errorf("line %d: unterminated section header", line)
			}
			current = strings.TrimSpace(raw[1:end])
			if _, ok := sections[current]; !ok {
				sections[current] = map[string]string{}
			}
			continue
		}
		eq := strings.IndexByte(raw, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", line)
		}
		key := strings.TrimSpace(raw[:eq])
		val := parseValue(strings.TrimSpace(raw[eq+1:]))
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", line)
		}
		sections[current][key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return sections, nil
}

// parseValue strips surrounding quotes, or trims a trailing inline comment from
// a bare value.
func parseValue(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		q := v[0]
		if end := strings.IndexByte(v[1:], q); end >= 0 {
			return v[1 : 1+end]
		}
	}
	if hash := strings.IndexByte(v, '#'); hash >= 0 {
		v = strings.TrimSpace(v[:hash])
	}
	return v
}
