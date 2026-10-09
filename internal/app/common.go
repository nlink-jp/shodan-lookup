package app

import (
	"flag"
)

// parseInterleaved parses flags that appear anywhere among the positional
// arguments, and returns the positionals.
//
// Go's flag package stops at the first non-flag argument, so a plain Parse
// would read `get CVE-2021-44228 --json` as two targets and silently ignore the
// flag. Writing the target first is the natural way to type this, and a flag
// that is quietly dropped is worse than one that is rejected — so parse in
// rounds, taking one positional at a time.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
}
