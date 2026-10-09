package ipaddr

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nlink-jp/shodan-lookup/internal/termsafe"
)

// Term is one whitespace-separated part of a Shodan query, split outside
// double quotes. A filter term is name:value with the colon outside quotes
// (Filter non-empty); anything else is free text.
type Term struct {
	Raw     string // the term as written
	Negated bool   // a leading '-': exclude what the filter matches
	Filter  string // the filter name, as written; "" for free text
	Value   string // the filter value with surrounding quotes removed
}

// MaxQueryLen bounds a query before any parsing: a query is typed by a person
// or written by a model, and nothing legitimate is longer.
const MaxQueryLen = 1000

// Lex splits a query into terms. An unbalanced double quote is refused here:
// upstream answers it with a 500 that cannot be told from a timeout
// (measured), so it must never be sent.
func Lex(q string) ([]Term, error) {
	if strings.TrimSpace(q) == "" {
		return nil, &Error{Reason: "the query is empty"}
	}
	if utf8.RuneCountInString(q) > MaxQueryLen {
		return nil, &Error{Reason: "the query is longer than 1000 characters"}
	}
	// Terms are separated by ASCII spaces and tabs only. Any other space,
	// line break or control character is refused: what Shodan reads as a
	// separator is not documented, and a term this gate did not see as one is
	// a term it did not check.
	for _, r := range q {
		if r == ' ' || r == '\t' {
			continue
		}
		if unicode.IsSpace(r) || unicode.IsControl(r) || termsafe.Obeyed(r) || !utf8.ValidRune(r) || r == utf8.RuneError {
			return nil, &Error{Reason: "the query holds a line break, a control character or a space other than an ASCII space or tab; separate terms with spaces"}
		}
	}
	var terms []string
	var cur strings.Builder
	inQuote := false
	for _, r := range q {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case !inQuote && (r == ' ' || r == '\t'):
			if cur.Len() > 0 {
				terms = append(terms, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if inQuote {
		return nil, &Error{Reason: "a double quote is not closed in the query"}
	}
	if cur.Len() > 0 {
		terms = append(terms, cur.String())
	}
	out := make([]Term, 0, len(terms))
	for _, raw := range terms {
		out = append(out, parseTerm(raw))
	}
	return out, nil
}

func parseTerm(raw string) Term {
	t := Term{Raw: raw}
	body := raw
	if strings.HasPrefix(body, "-") && len(body) > 1 {
		body = body[1:]
		t.Negated = true
	}
	// A filter name is the run of name characters before a colon that is
	// itself outside quotes; a term that starts with a quote is free text.
	i := strings.IndexByte(body, ':')
	if i <= 0 || !isFilterName(body[:i]) {
		t.Negated = false
		return t
	}
	t.Filter = body[:i]
	t.Value = unquote(body[i+1:])
	return t
}

func isFilterName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

func unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}

// CheckQuery refuses a query that would send a non-public address, and
// returns its terms for the caller's own checks (filter names, plan
// restrictions). Two checks:
//
//   - ip: and net: values (comma-separated lists allowed) must parse and be
//     public; a value that cannot be parsed is refused, since what cannot be
//     checked is not sent.
//   - Every address literal anywhere in the query — free text, quoted text,
//     another filter's value, a prefix written without net: — is judged too.
//     Checking only terms that start with ip: let +ip:10.0.0.1, (ip:…) and
//     hostname:10.0.0.1 through.
//
// Names (hostname:intranet.example) cannot be judged by their spelling; that
// residual is documented, not guessed at.
func CheckQuery(q string) ([]Term, error) {
	terms, err := Lex(q)
	if err != nil {
		return nil, err
	}
	for _, t := range terms {
		switch strings.ToLower(t.Filter) {
		case "ip":
			for v := range strings.SplitSeq(t.Value, ",") {
				if _, err := Parse(v); err != nil {
					return nil, err
				}
			}
		case "net":
			for v := range strings.SplitSeq(t.Value, ",") {
				if _, err := CheckPrefix(v); err != nil {
					return nil, err
				}
			}
		}
	}
	if err := checkLiterals(q, terms); err != nil {
		return nil, err
	}
	return terms, nil
}

// ipv4Literal finds every dotted quad anywhere in a query, glued to a word or
// not (hostname:10.0.0.1, e10.0.0.1). ipv6Run finds runs an IPv6 address can
// be written with; runs are taken from each term as written and from its
// value with the filter name removed (hostname: ends in a hex letter).
var (
	ipv4Literal = regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`)
	ipv6Run     = regexp.MustCompile(`[0-9A-Fa-f:.%]*:[0-9A-Fa-f:.%]*`)
)

func checkLiterals(q string, terms []Term) error {
	for _, cand := range ipv4Literal.FindAllString(q, -1) {
		addr, err := netip.ParseAddr(cand)
		if err != nil {
			return &Error{Input: cand, Reason: "looks like an IPv4 address that cannot be checked (a zero-padded or out-of-range octet), so it is not sent"}
		}
		if c, via := Classify(addr); c != "" {
			return refused(cand, c, via)
		}
	}
	for _, t := range terms {
		// Both the term as written and its value: fe80::1 lexes as a filter
		// named fe80, while hostname:fe80::1 needs its name removed.
		for _, run := range append(ipv6Run.FindAllString(t.Raw, -1), ipv6Run.FindAllString(t.Value, -1)...) {
			for _, cand := range v6Candidates(run) {
				addr, err := netip.ParseAddr(cand)
				if err != nil || !addr.Is6() {
					continue // not an address: a time, a colon-separated fingerprint
				}
				if strings.Contains(cand, "%") {
					return &Error{Input: cand, Reason: "is a zoned address, which names an interface on this machine"}
				}
				if c, via := Classify(addr.Unmap()); c != "" {
					return refused(cand, c, via)
				}
				break
			}
		}
	}
	return nil
}

// v6Candidates is the run as found, without a single leading colon left by a
// prefix such as +ip: or (ip:, and without trailing sentence punctuation. A
// run is never cut further: a colon-separated fingerprint holds eight-group
// stretches that read as addresses and are not.
func v6Candidates(run string) []string {
	out := []string{run, strings.TrimRight(run, ".")}
	if strings.HasPrefix(run, ":") && !strings.HasPrefix(run, "::") {
		out = append(out, run[1:], strings.TrimRight(run[1:], "."))
	}
	return out
}
