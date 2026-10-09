package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// isolate points config and cache discovery at a temp dir and clears the
// tool's environment, so a test never reads or clears the developer's own
// config or cache. HOME is replaced too: ~/.config is searched even when
// XDG_CONFIG_HOME is set.
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
	// The suite is offline by construction, not by luck: a command that one
	// day reaches for the network from a test lands on a closed local port
	// instead of on the real API — and carries no real key there.
	t.Setenv("SHODAN_LOOKUP_BASE_URL", "http://127.0.0.1:1")
	return dir
}

// The scaffold's contract with the Homebrew formula: `brew test` runs
// `--version`, so all three spellings must agree byte for byte. A formula that
// tests a spelling the tool answers differently is a release that ships broken.
func TestVersionSpellingsAreIdentical(t *testing.T) {
	outputs := make(map[string]string)
	for _, arg := range []string{"version", "--version", "-v"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{arg}, "1.2.3", nil, &stdout, &stderr); code != exitOK {
			t.Fatalf("%s: exit code = %d, want %d (stderr: %s)", arg, code, exitOK, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Errorf("%s: wrote to stderr: %s", arg, stderr.String())
		}
		outputs[arg] = stdout.String()
	}
	if outputs["version"] != outputs["--version"] {
		t.Errorf("version and --version differ:\n version: %q\n--version: %q", outputs["version"], outputs["--version"])
	}
	if outputs["version"] != outputs["-v"] {
		t.Errorf("version and -v differ:\n version: %q\n     -v: %q", outputs["version"], outputs["-v"])
	}
	if !strings.HasPrefix(outputs["version"], "shodan-lookup 1.2.3\n") {
		t.Errorf("version banner does not lead with the binary name and version: %q", outputs["version"])
	}
}

func TestHelpGoesToStdoutAndSucceeds(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{arg}, "dev", nil, &stdout, &stderr); code != exitOK {
			t.Errorf("%s: exit code = %d, want %d", arg, code, exitOK)
		}
		if stderr.Len() != 0 {
			t.Errorf("%s: wrote to stderr: %s", arg, stderr.String())
		}
		if !strings.Contains(stdout.String(), "Usage:") {
			t.Errorf("%s: help text has no Usage section", arg)
		}
	}
}

// No arguments is a usage error, and the usage text belongs on stderr so a
// piped stdout stays clean.
func TestNoArgsIsUsageErrorOnStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, "dev", nil, &stdout, &stderr); code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if stdout.Len() != 0 {
		t.Errorf("wrote to stdout: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Errorf("stderr has no usage text: %s", stderr.String())
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"whoami"}, "dev", nil, &stdout, &stderr); code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr.String(), `unknown command "whoami"`) {
		t.Errorf("stderr does not name the unknown command: %s", stderr.String())
	}
}

// usageCommands reads the command names out of the usage text's Commands
// block, so the tests below follow the help rather than a second list.
func usageCommands(t *testing.T) []string {
	t.Helper()
	var buf bytes.Buffer
	usage(&buf)
	_, after, ok := strings.Cut(buf.String(), "Commands:\n")
	if !ok {
		t.Fatal("usage text has no Commands block")
	}
	block, _, _ := strings.Cut(after, "\n\n")
	seen := map[string]bool{}
	var cmds []string
	for _, line := range strings.Split(block, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || seen[fields[0]] {
			continue
		}
		seen[fields[0]] = true
		cmds = append(cmds, fields[0])
	}
	if len(cmds) < 3 {
		t.Fatalf("parsed only %v from the usage text — the parser is broken", cmds)
	}
	return cmds
}

// Every command named in the usage text must be dispatched. This is what keeps
// the scaffold's help honest as commands are implemented: adding a line to the
// usage text without a case in the switch fails here.
func TestUsageCommandsAreDispatched(t *testing.T) {
	isolate(t)
	for _, cmd := range usageCommands(t) {
		var stdout, stderr bytes.Buffer
		// An empty stdin lets `mcp` return at once instead of serving.
		run([]string{cmd}, "dev", strings.NewReader(""), &stdout, &stderr)
		if strings.Contains(stderr.String(), "unknown command") {
			t.Errorf("%s is documented in the usage text but not dispatched", cmd)
		}
	}
}

// paragraphWith returns the blank-line-delimited paragraph of text that
// contains marker, or "" when none does.
func paragraphWith(text, marker string) string {
	for _, p := range strings.Split(text, "\n\n") {
		if strings.Contains(p, marker) {
			return p
		}
	}
	return ""
}

// backticked returns the `quoted` tokens of s, sorted.
func backticked(s string) []string {
	var out []string
	parts := strings.Split(s, "`")
	for i := 1; i < len(parts); i += 2 {
		out = append(out, parts[i])
	}
	sort.Strings(out)
	return out
}

// Which commands are unimplemented is read off the program's behaviour, and
// every document that talks about it is held to that — in both directions.
// While a command is a placeholder it must refuse (a scaffold that exits 0 on
// `host 192.0.2.1` would read as "nothing exposed") and the help and both READMEs
// must name it. The day it lands, they must stop: a status sentence guarded
// only while it is true outlives the day it becomes false.
func TestNotImplementedStatementsMatchBehaviour(t *testing.T) {
	isolate(t)

	var actual []string
	for _, cmd := range usageCommands(t) {
		var stdout, stderr bytes.Buffer
		code := run([]string{cmd, "x"}, "dev", strings.NewReader(""), &stdout, &stderr)
		if !strings.Contains(stderr.String(), "not implemented") {
			continue
		}
		actual = append(actual, cmd)
		if code != exitError {
			t.Errorf("%s: says it is unimplemented but exits %d, want %d", cmd, code, exitError)
		}
		if stdout.Len() != 0 {
			t.Errorf("%s: an unimplemented command wrote to stdout: %s", cmd, stdout.String())
		}
	}
	sort.Strings(actual)

	var help bytes.Buffer
	usage(&help)
	helpSentence, _, _ := strings.Cut(paragraphWith(help.String(), "not implemented yet"), " are not implemented yet")
	helpNames := strings.Fields(strings.NewReplacer(",", " ", " and ", " ").Replace(helpSentence))
	sort.Strings(helpNames)

	readme := func(name, marker string) []string {
		raw, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return backticked(paragraphWith(string(raw), marker))
	}

	for where, named := range map[string][]string{
		"the usage text": helpNames,
		"README.md":      readme("README.md", "placeholders in this"),
		"README.ja.md":   readme("README.ja.md", "プレースホルダ"),
	} {
		if strings.Join(named, " ") != strings.Join(actual, " ") {
			t.Errorf("%s names %v as unimplemented, but the commands that refuse are %v", where, named, actual)
		}
	}
}

func TestCacheStatusOnAnEmptyCache(t *testing.T) {
	dir := isolate(t)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"cache", "status"}, "dev", nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}
	for _, want := range []string{filepath.Join(dir, "cache", "shodan-lookup"), "entries:      0",
		"host ttl:     12 hours", "count ttl:    1 hours", "search ttl:   24 hours", "api key: not set"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("text status is missing %q:\n%s", want, stdout.String())
		}
	}

	stdout.Reset()
	// The flag after the positional is the natural way to type it.
	if code := run([]string{"cache", "status", "--json"}, "dev", nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("--json: exit code = %d (stderr: %s)", code, stderr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("--json did not emit JSON: %v (raw: %s)", err, stdout.String())
	}
	for field, want := range map[string]any{"host_ttl_hours": 12.0, "count_ttl_hours": 1.0, "search_ttl_hours": 24.0, "api_key": "not set"} {
		if payload[field] != want {
			t.Errorf("%s = %v, want %v", field, payload[field], want)
		}
	}
}

// Whether a key is configured is diagnosable; what it is never appears.
func TestCacheStatusNeverPrintsTheKey(t *testing.T) {
	isolate(t)
	t.Setenv("SHODAN_LOOKUP_API_KEY", "sk-do-not-print")
	for _, args := range [][]string{{"cache", "status"}, {"cache", "status", "--json"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, "dev", nil, &stdout, &stderr); code != exitOK {
			t.Fatalf("%v: exit code = %d (stderr: %s)", args, code, stderr.String())
		}
		if strings.Contains(stdout.String()+stderr.String(), "sk-do-not-print") {
			t.Errorf("%v printed the key", args)
		}
		if !strings.Contains(stdout.String(), "set") {
			t.Errorf("%v does not say a key is set:\n%s", args, stdout.String())
		}
	}
}

// A zero TTL is shown as what it means.
func TestCacheStatusShowsATTLOfZeroAsNotCached(t *testing.T) {
	isolate(t)
	t.Setenv("SHODAN_LOOKUP_SEARCH_TTL_HOURS", "0")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"cache", "status"}, "dev", nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "search ttl:   0 (not cached)") {
		t.Errorf("a zero TTL is not shown as not cached:\n%s", stdout.String())
	}
}

// "I set it and nothing changed" is diagnosed by one fact: which file was
// read. cache status always states it — the path, or that there was none and
// where it looked.
func TestCacheStatusReportsTheConfigFileRead(t *testing.T) {
	dir := isolate(t)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"cache", "status"}, "dev", nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "config: none") ||
		!strings.Contains(stdout.String(), filepath.Join(dir, "home", ".config", "shodan-lookup", "config.toml")) {
		t.Errorf("with no config file, status does not say so and list where it looked:\n%s", stdout.String())
	}

	confDir := filepath.Join(dir, "home", ".config", "shodan-lookup")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	confFile := filepath.Join(confDir, "config.toml")
	if err := os.WriteFile(confFile, []byte("[cache]\nsearch_ttl_hours = 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	if code := run([]string{"cache", "status"}, "dev", nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "config: "+confFile) || !strings.Contains(stdout.String(), "search ttl:   7 hours") {
		t.Errorf("status does not name the config file it read, or did not apply it:\n%s", stdout.String())
	}

	stdout.Reset()
	if code := run([]string{"cache", "status", "--json"}, "dev", nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("--json: exit code = %d (stderr: %s)", code, stderr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("--json did not emit JSON: %v", err)
	}
	if payload["config_path"] != confFile {
		t.Errorf("config_path = %v, want %s", payload["config_path"], confFile)
	}
	if _, present := payload["config_searched"]; present {
		t.Error("config_searched is listed although a file was read")
	}
}

// A config path the operator named and mistyped must stop the command, not
// fall back to the defaults.
func TestExplicitMissingConfigStopsTheCommand(t *testing.T) {
	dir := isolate(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"cache", "status", "--config", filepath.Join(dir, "typo.toml")}, "dev", nil, &stdout, &stderr)
	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr.String(), "typo.toml") {
		t.Errorf("stderr does not name the missing file: %s", stderr.String())
	}
}

// clear removes what the cache wrote and nothing else in the directory.
func TestCacheClearRemovesOnlyCacheEntries(t *testing.T) {
	dir := isolate(t)
	cacheDir := filepath.Join(dir, "cache", "shodan-lookup")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bystander := filepath.Join(cacheDir, "notes.txt")
	if err := os.WriteFile(bystander, []byte("not a cache entry"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"cache", "clear"}, "dev", nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "removed 0 cached entries") {
		t.Errorf("unexpected clear output: %s", stdout.String())
	}
	if _, err := os.Stat(bystander); err != nil {
		t.Errorf("clear removed a file the cache did not write: %v", err)
	}
}

func TestCacheRejectsBadSubcommands(t *testing.T) {
	isolate(t)
	for _, args := range [][]string{{"cache"}, {"cache", "purge"}, {"cache", "status", "clear"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, "dev", nil, &stdout, &stderr); code != exitError {
			t.Errorf("%v: exit code = %d, want %d", args, code, exitError)
		}
		if stderr.Len() == 0 {
			t.Errorf("%v: no diagnostic on stderr", args)
		}
	}
}

// A broken config is a configuration error for every command that loads it,
// and the message names the setting.
func TestBadConfigIsReportedByName(t *testing.T) {
	isolate(t)
	t.Setenv("SHODAN_LOOKUP_BASE_URL", "http://shodan.example.test")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"cache", "status"}, "dev", nil, &stdout, &stderr); code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr.String(), "base_url") {
		t.Errorf("stderr does not name the setting: %s", stderr.String())
	}
}

// The file used for the 2026-10-09 measurements has a top-level api_key. Every
// command that loads the config must stop on it and say where the key goes.
func TestATopLevelAPIKeyStopsCommandsWithDirections(t *testing.T) {
	dir := isolate(t)
	confDir := filepath.Join(dir, "home", ".config", "shodan-lookup")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "config.toml"), []byte("api_key = \"sk-measured\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"cache", "status"}, {"mcp"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, "dev", strings.NewReader(""), &stdout, &stderr); code != exitError {
			t.Errorf("%v: exit code = %d, want %d", args, code, exitError)
		}
		if !strings.Contains(stderr.String(), "[api]") || strings.Contains(stderr.String(), "sk-measured") {
			t.Errorf("%v: diagnostic does not point at [api], or quotes the key: %s", args, stderr.String())
		}
	}
}
