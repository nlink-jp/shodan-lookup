// Package termsafe holds the one list of characters a terminal obeys rather
// than shows. Third-party text reaches this tool's output — and in Shodan's
// case the most hostile kind: a service banner, an HTML title or a
// certificate subject is written by the very host under investigation — and
// that output is read by a human in a terminal emulator.
//
// Vendored from cve-lookup, where the list had once been written out three
// times and the copies disagreed (one lacked the bidirectional controls). A
// list that must agree with itself is kept once.
package termsafe

// Obeyed reports whether a terminal acts on r instead of drawing it: the C0
// and C1 controls, DEL, and the Unicode bidirectional controls. Newline, tab
// and carriage return are C0 and are reported too — a caller that lets one of
// them through says so at the call site.
func Obeyed(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f:
		return true
	case r >= 0x80 && r <= 0x9f:
		return true
	case r >= 0x202a && r <= 0x202e: // LRE RLE PDF LRO RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI RLI FSI PDI
		return true
	case r == 0x200e, r == 0x200f, r == 0x061c: // LRM RLM ALM
		return true
	}
	return false
}
