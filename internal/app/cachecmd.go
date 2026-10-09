package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/config"
)

func runCache(args []string, stdout, stderr io.Writer) int {
	var jsonOut bool
	var configPath string
	fs := flag.NewFlagSet("cache", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	fs.BoolVar(&jsonOut, "json", false, "JSON output")
	fs.BoolVar(&jsonOut, "j", false, "JSON output (shorthand)")
	fs.StringVar(&configPath, "config", "", "config file path")
	fs.StringVar(&configPath, "c", "", "config file path (shorthand)")

	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "shodan-lookup: cache takes one subcommand: status or clear")
		return exitError
	}

	cfg, err := config.Load(configPath, 0)
	if err != nil {
		fmt.Fprintf(stderr, "shodan-lookup: %v\n", err)
		return exitError
	}
	store := &cache.Store{Dir: cfg.CacheDir}

	switch positional[0] {
	case "status":
		st := store.Stat()
		if jsonOut {
			payload := struct {
				cache.Stats
				HostTTLHours   float64  `json:"host_ttl_hours"`
				CountTTLHours  float64  `json:"count_ttl_hours"`
				SearchTTLHours float64  `json:"search_ttl_hours"`
				APIKey         string   `json:"api_key"`
				ConfigPath     string   `json:"config_path"`
				ConfigSearched []string `json:"config_searched,omitempty"`
			}{
				Stats:          st,
				HostTTLHours:   cfg.HostTTL.Hours(),
				CountTTLHours:  cfg.CountTTL.Hours(),
				SearchTTLHours: cfg.SearchTTL.Hours(),
				APIKey:         keyState(cfg),
				ConfigPath:     cfg.Path,
			}
			if cfg.Path == "" {
				payload.ConfigSearched = config.SearchPaths()
			}
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(payload); err != nil {
				fmt.Fprintf(stderr, "shodan-lookup: %v\n", err)
				return exitError
			}
			return exitOK
		}
		// Which file was read is the one thing that diagnoses "I set it and
		// nothing changed", so it is always stated — including when none was.
		if cfg.Path != "" {
			fmt.Fprintf(stdout, "config: %s\n", cfg.Path)
		} else {
			fmt.Fprintln(stdout, "config: none (built-in defaults); looked in:")
			for _, p := range config.SearchPaths() {
				fmt.Fprintf(stdout, "  %s\n", p)
			}
		}
		fmt.Fprintf(stdout, "api key: %s\n", keyState(cfg))
		fmt.Fprintf(stdout, "cache: %s\n", st.Dir)
		fmt.Fprintf(stdout, "  entries:      %d  (%s)\n", st.Entries, humanBytes(st.Bytes))
		fmt.Fprintf(stdout, "  host ttl:     %s\n", ttlText(cfg.HostTTL.Hours()))
		fmt.Fprintf(stdout, "  count ttl:    %s\n", ttlText(cfg.CountTTL.Hours()))
		fmt.Fprintf(stdout, "  search ttl:   %s\n", ttlText(cfg.SearchTTL.Hours()))
		if st.Entries > 0 {
			fmt.Fprintf(stdout, "  written:      %s .. %s\n",
				st.Oldest.Format("2006-01-02 15:04"), st.Newest.Format("2006-01-02 15:04"))
			// The TTL is applied when reading, so entries older than it are
			// already dead weight rather than answers still in use.
			fmt.Fprintln(stdout, "  note: TTLs are applied at read time, so lowering one in the")
			fmt.Fprintln(stdout, "        config expires entries already on disk.")
		}
		return exitOK

	case "clear":
		n, err := store.Clear()
		if err != nil {
			fmt.Fprintf(stderr, "shodan-lookup: clear cache: %v\n", err)
			return exitError
		}
		if jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(map[string]any{"removed": n, "dir": store.Dir}); err != nil {
				fmt.Fprintf(stderr, "shodan-lookup: %v\n", err)
				return exitError
			}
			return exitOK
		}
		fmt.Fprintf(stdout, "removed %d cached entr%s from %s\n", n, plural(n, "y", "ies"), store.Dir)
		return exitOK

	default:
		fmt.Fprintf(stderr, "shodan-lookup: unknown cache subcommand %q (want status or clear)\n", positional[0])
		return exitError
	}
}

// keyState says whether a key is configured, never what it is.
func keyState(cfg *config.Config) string {
	if cfg.HasKey() {
		return "set"
	}
	return "not set"
}

func ttlText(hours float64) string {
	if hours == 0 {
		return "0 (not cached)"
	}
	return fmt.Sprintf("%g hours", hours)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 3; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
