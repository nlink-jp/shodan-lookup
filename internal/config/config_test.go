package config

import (
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// isolate points config discovery at an empty temp tree and clears every
// variable this package reads, so a test never sees the developer's own key.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("SHODAN_API_KEY", "")
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "SHODAN_LOOKUP_") {
			t.Setenv(name, "")
		}
	}
	return dir
}

func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsWithoutAnyFile(t *testing.T) {
	dir := isolate(t)
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Path != "" {
		t.Errorf("Path = %q, want empty", cfg.Path)
	}
	if cfg.HasKey() {
		t.Error("a key appeared from nowhere")
	}
	if cfg.BaseURL != DefaultBaseURL || cfg.DefaultServices != DefaultServices || cfg.DefaultVulns != DefaultVulns ||
		cfg.BannerBytes != DefaultBannerBytes || cfg.CreditFloor != DefaultCreditFloor ||
		cfg.HostTTL != DefaultHostTTL || cfg.CountTTL != DefaultCountTTL || cfg.SearchTTL != DefaultSearchTTL ||
		cfg.Timeout != DefaultTimeout || cfg.MinInterval != DefaultMinInterval {
		t.Errorf("defaults not applied: %+v", cfg.Redacted())
	}
	if want := filepath.Join(dir, "cache", "shodan-lookup"); cfg.CacheDir != want {
		t.Errorf("CacheDir = %q, want %q", cfg.CacheDir, want)
	}
}

// The pacing default is half the documented rate, by design (RFP §2). A change
// to either constant that loses that relation should be a decision, not drift.
func TestPacingDefaultIsHalfTheDocumentedRate(t *testing.T) {
	if DefaultMinInterval != 2*DocumentedMinInterval {
		t.Errorf("DefaultMinInterval = %v, want twice the documented %v", DefaultMinInterval, DocumentedMinInterval)
	}
}

func TestEveryKeyIsApplied(t *testing.T) {
	dir := isolate(t)
	p := writeConfig(t, dir, `
[api]
key = "k-file"
base_url = "https://shodan.example.test/"
[query]
default_services = 7
default_vulns = 9
banner_bytes = 256
[search]
credit_floor = 0
[cache]
host_ttl_hours = 2
count_ttl_hours = 0.5
search_ttl_hours = 0
dir = "~/sl-cache"
[network]
timeout_seconds = 4
[limits]
min_interval_ms = 1500
`)
	cfg, err := Load(p, 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Path != p || cfg.APIKey != "k-file" || cfg.BaseURL != "https://shodan.example.test" ||
		cfg.DefaultServices != 7 || cfg.DefaultVulns != 9 || cfg.BannerBytes != 256 || cfg.CreditFloor != 0 ||
		cfg.HostTTL != 2*time.Hour || cfg.CountTTL != 30*time.Minute || cfg.SearchTTL != 0 ||
		cfg.Timeout != 4*time.Second || cfg.MinInterval != 1500*time.Millisecond {
		t.Errorf("file values not applied: %+v", cfg.Redacted())
	}
	if want := filepath.Join(dir, "home", "sl-cache"); cfg.CacheDir != want {
		t.Errorf("CacheDir = %q, want %q (~ expanded)", cfg.CacheDir, want)
	}
}

// The file used for the 2026-10-09 measurements holds `api_key = "..."` on its
// own line — the shape other Shodan tooling uses. It must be refused with
// directions, not silently read as "no key".
func TestATopLevelKeyIsRefusedWithDirections(t *testing.T) {
	for _, body := range []string{`api_key = "abc"`, `key = "abc"`} {
		dir := isolate(t)
		_, err := Load(writeConfig(t, dir, body+"\n"), 0)
		if err == nil {
			t.Fatalf("%s: accepted", body)
		}
		if !strings.Contains(err.Error(), "[api]") || strings.Contains(err.Error(), "abc") {
			t.Errorf("%s: error does not point at [api], or quotes the value: %v", body, err)
		}
	}
	dir := isolate(t)
	if _, err := Load(writeConfig(t, dir, "colour = \"blue\"\n"), 0); err == nil || !strings.Contains(err.Error(), "colour") {
		t.Errorf("an unknown top-level key is not refused by name: %v", err)
	}
}

func TestUnknownInputIsRefusedByName(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"[apii]\nkey = \"x\"\n", "[apii]"},
		{"[api]\ntoken = \"x\"\n", "token"},
		{"[cache]\nhost_ttl_minutes = 5\n", "host_ttl_minutes"},
	} {
		dir := isolate(t)
		_, err := Load(writeConfig(t, dir, tc.body), 0)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: error %v does not name %q", tc.body, err, tc.want)
		}
	}
}

// A key that is present was given: "" is refused, not skipped.
func TestAPresentEmptyValueIsRefused(t *testing.T) {
	for _, body := range []string{
		"[api]\nkey = \"\"\n",
		"[api]\nbase_url = \"\"\n",
		"[cache]\ndir = \"\"\n",
		"[query]\ndefault_services = \"\"\n",
		"[cache]\nhost_ttl_hours = \"\"\n",
	} {
		dir := isolate(t)
		if _, err := Load(writeConfig(t, dir, body), 0); err == nil {
			t.Errorf("%q: accepted", body)
		}
	}
}

func TestNumbersOutsideTheirRangeAreRefused(t *testing.T) {
	for _, body := range []string{
		"[query]\ndefault_services = 0\n",
		"[query]\ndefault_services = 501\n",
		"[query]\ndefault_vulns = -1\n",
		"[query]\nbanner_bytes = 63\n",
		"[query]\nbanner_bytes = 1.5\n",
		"[search]\ncredit_floor = -1\n",
		"[cache]\nhost_ttl_hours = -1\n",
		"[cache]\nhost_ttl_hours = NaN\n",
		"[cache]\ncount_ttl_hours = Inf\n",
		"[cache]\nsearch_ttl_hours = 1e300\n",
		"[cache]\nhost_ttl_hours = 1e-30\n",
		"[network]\ntimeout_seconds = 0\n",
		"[network]\ntimeout_seconds = NaN\n",
		"[limits]\nmin_interval_ms = 0\n",
		"[limits]\nmin_interval_ms = 600001\n",
	} {
		dir := isolate(t)
		if _, err := Load(writeConfig(t, dir, body), 0); err == nil {
			t.Errorf("%q: accepted", body)
		}
	}
}

// A zero TTL is a stated choice — "do not cache this kind" — so that a terms
// change forbidding caching needs no code change.
func TestAZeroTTLTurnsCachingOff(t *testing.T) {
	dir := isolate(t)
	cfg, err := Load(writeConfig(t, dir, "[cache]\nhost_ttl_hours = 0\ncount_ttl_hours = 0\nsearch_ttl_hours = 0\n"), 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HostTTL != 0 || cfg.CountTTL != 0 || cfg.SearchTTL != 0 {
		t.Errorf("TTLs = %v %v %v, want all 0", cfg.HostTTL, cfg.CountTTL, cfg.SearchTTL)
	}
}

func TestExplicitMissingPathIsAnError(t *testing.T) {
	dir := isolate(t)
	if _, err := Load(filepath.Join(dir, "typo.toml"), 0); err == nil || !strings.Contains(err.Error(), "typo.toml") {
		t.Errorf("a missing explicit config is not an error naming it: %v", err)
	}
}

func TestBaseURLMustNotCarryTheKeyOverPlaintext(t *testing.T) {
	ok := []string{"https://api.shodan.io", "http://127.0.0.1:8080", "http://[::1]:9", "http://localhost:1"}
	bad := map[string]string{
		"http://api.shodan.io":             "https",
		"ftp://api.shodan.io":              "scheme",
		"https://user:pw@api.shodan.io":    "credentials",
		"https://api.shodan.io/?key=x":     "query",
		"https://api.shodan.io/?":          "query",
		"https://api.shodan.io/#frag":      "fragment",
		"https://":                         "host",
		"http://192.168.1.10":              "https",
		"https://api.shodan.io/%zz?key=sk": "not a valid URL",
	}
	for _, u := range ok {
		if err := validateBaseURL(u); err != nil {
			t.Errorf("%s: refused: %v", u, err)
		}
	}
	for u, want := range bad {
		err := validateBaseURL(u)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v does not mention %q", u, err, want)
			continue
		}
		if strings.Contains(err.Error(), "pw") || strings.Contains(err.Error(), "sk") {
			t.Errorf("%s: the error quotes a secret from the URL: %v", u, err)
		}
	}
}

func TestEnvironmentOverridesTheFile(t *testing.T) {
	dir := isolate(t)
	p := writeConfig(t, dir, "[api]\nkey = \"k-file\"\n[cache]\nhost_ttl_hours = 3\n")
	t.Setenv("SHODAN_LOOKUP_HOST_TTL_HOURS", "0")
	t.Setenv("SHODAN_LOOKUP_MIN_INTERVAL_MS", "3000")
	t.Setenv("SHODAN_LOOKUP_CREDIT_FLOOR", "50")
	cfg, err := Load(p, 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HostTTL != 0 || cfg.MinInterval != 3*time.Second || cfg.CreditFloor != 50 {
		t.Errorf("environment not applied: %+v", cfg.Redacted())
	}
	t.Setenv("SHODAN_LOOKUP_CREDIT_FLOOR", "lots")
	if _, err := Load(p, 0); err == nil || !strings.Contains(err.Error(), "SHODAN_LOOKUP_CREDIT_FLOOR") {
		t.Errorf("a bad environment value is not refused by name: %v", err)
	}
}

// SHODAN_LOOKUP_API_KEY wins, then SHODAN_API_KEY, then the file.
func TestKeyPrecedence(t *testing.T) {
	dir := isolate(t)
	p := writeConfig(t, dir, "[api]\nkey = \"k-file\"\n")
	check := func(want string) {
		t.Helper()
		cfg, err := Load(p, 0)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.APIKey != want {
			t.Errorf("APIKey = %q, want %q", cfg.APIKey, want)
		}
	}
	check("k-file")
	t.Setenv("SHODAN_API_KEY", "k-alias")
	check("k-alias")
	t.Setenv("SHODAN_LOOKUP_API_KEY", "k-own")
	check("k-own")
}

func TestRedactedNeverRendersTheKey(t *testing.T) {
	cfg := &Config{APIKey: "sekrit"}
	if r := cfg.Redacted(); r.APIKey != "[set]" {
		t.Errorf("Redacted().APIKey = %q", r.APIKey)
	}
	if cfg.APIKey != "sekrit" {
		t.Error("Redacted modified the original")
	}
	if r := (&Config{}).Redacted(); r.APIKey != "" {
		t.Errorf("an absent key is rendered as %q", r.APIKey)
	}
}

func TestTimeoutOverrideWins(t *testing.T) {
	isolate(t)
	t.Setenv("SHODAN_LOOKUP_TIMEOUT_SECONDS", "9")
	cfg, err := Load("", 5*time.Second)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want the override", cfg.Timeout)
	}
}

func TestTimeoutSeconds(t *testing.T) {
	if d, err := TimeoutSeconds(2.5); err != nil || d != 2500*time.Millisecond {
		t.Errorf("2.5 → %v, %v", d, err)
	}
	for _, s := range []float64{0, -1, 3601, math.NaN(), math.Inf(1), 1e-12} {
		if _, err := TimeoutSeconds(s); err == nil {
			t.Errorf("%g: accepted", s)
		}
	}
}

// ~/.config is searched even when XDG_CONFIG_HOME is set.
func TestSearchPathsKeepHomeConfigBehindXDG(t *testing.T) {
	dir := isolate(t)
	paths := SearchPaths()
	want := []string{
		filepath.Join(dir, "config", "shodan-lookup", "config.toml"),
		filepath.Join(dir, "home", ".config", "shodan-lookup", "config.toml"),
	}
	if len(paths) < 2 || paths[0] != want[0] || paths[1] != want[1] {
		t.Fatalf("SearchPaths = %v, want it to start with %v", paths, want)
	}
	if runtime.GOOS == "darwin" && (len(paths) != 3 || !strings.Contains(paths[2], "Application Support")) {
		t.Errorf("macOS search path missing: %v", paths)
	}

	home := filepath.Join(dir, "home", ".config", "shodan-lookup")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte("[search]\ncredit_floor = 5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CreditFloor != 5 || cfg.Path != filepath.Join(home, "config.toml") {
		t.Errorf("~/.config file not read with XDG_CONFIG_HOME set: path %q, floor %d", cfg.Path, cfg.CreditFloor)
	}
}

func TestParseValue(t *testing.T) {
	for in, want := range map[string]string{
		`"quoted # not a comment"`: "quoted # not a comment",
		`'single'`:                 "single",
		`bare # comment`:           "bare",
		`12`:                       "12",
	} {
		if got := parseValue(in); got != want {
			t.Errorf("parseValue(%s) = %q, want %q", in, got, want)
		}
	}
}

// The example file is what an operator copies first. It must load as it ships,
// and uncommenting every setting at its documented default must change nothing
// — an example that disagrees with the code is the first thing a user trips on.
func TestTheExampleFileLoadsAndStatesTheDefaults(t *testing.T) {
	isolate(t)
	// The example states the default for an unset XDG_CACHE_HOME.
	t.Setenv("XDG_CACHE_HOME", "")
	raw, err := os.ReadFile(filepath.Join("..", "..", "config.example.toml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg, err := Load(writeConfig(t, dir, string(raw)), 0)
	if err != nil {
		t.Fatalf("the example as shipped does not load: %v", err)
	}
	if cfg.HasKey() {
		t.Error("the example as shipped sets a key")
	}

	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		if settingLine.MatchString(line) {
			line = strings.TrimPrefix(line, "# ")
		}
		lines = append(lines, line)
	}
	got, err := Load(writeConfig(t, dir, strings.Join(lines, "\n")), 0)
	if err != nil {
		t.Fatalf("the example with every setting uncommented does not load: %v", err)
	}
	want, _ := Load("", 0)
	got.Path, want.Path = "", ""
	if *got != *want {
		t.Errorf("the example's stated defaults differ from the code's:\n got  %+v\n want %+v", got.Redacted(), want.Redacted())
	}
}

// settingLine matches a commented-out setting in the example file — "# key =
// value" — and not prose that happens to quote one.
var settingLine = regexp.MustCompile(`^# [a-z_]+ = \S`)
