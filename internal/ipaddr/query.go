package ipaddr

import (
	"strings"
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
		return nil, &Error{Input: q, Reason: "the query is empty"}
	}
	if len(q) > MaxQueryLen {
		return nil, &Error{Input: q[:40] + "…", Reason: "the query is longer than 1000 characters"}
	}
	var terms []string
	var cur strings.Builder
	inQuote := false
	for _, r := range q {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case !inQuote && (r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			if cur.Len() > 0 {
				terms = append(terms, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if inQuote {
		return nil, &Error{Input: q, Reason: "a double quote is not closed"}
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

// CheckQuery refuses a query whose ip: or net: values are not publicly
// routable, and returns its terms for the caller's own checks (filter names,
// plan restrictions). Values may be comma-separated lists. A value of these
// two filters that cannot be parsed is refused too: what cannot be checked is
// not sent. Names inside hostname: or org: cannot be judged by their spelling;
// that residual is documented, not guessed at.
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
	return terms, nil
}
