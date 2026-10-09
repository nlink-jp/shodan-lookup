package app

import (
	"bytes"
	"fmt"
	"reflect"
	"unicode/utf8"

	"github.com/nlink-jp/shodan-lookup/internal/termsafe"
)

// Vendored from cve-lookup (its correction 22). Remembering to call visible()
// at every print site does not scale: cve-lookup's review found five sites that
// printed upstream strings as they arrived. So the text renderers never see
// upstream's strings at all. forText rewrites every string a result holds
// before the first byte is printed, and a print site can no longer be wrong.
// Here it matters more than anywhere in the fleet: a banner is written by the
// very host under investigation.

// multilineFields are the fields printed behind a gutter by block(), and the
// only ones in which a newline or a tab survives. Everywhere else an embedded
// newline would forge a line of this tool's own output.
var multilineFields = map[string]bool{"Banner": true, "Text": true, "Summary": true, "Lines": true}

// forText makes every string reachable from v safe to print on a terminal, in
// place, and returns v. v must be a pointer.
func forText[T any](v *T) *T {
	makeVisible(reflect.ValueOf(v), false)
	return v
}

func makeVisible(v reflect.Value, multiline bool) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			makeVisible(v.Elem(), multiline)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if f := v.Type().Field(i); f.IsExported() {
				makeVisible(v.Field(i), multilineFields[f.Name])
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return // raw JSON: printed through block(), which escapes it
		}
		for i := 0; i < v.Len(); i++ {
			makeVisible(v.Index(i), multiline)
		}
	case reflect.Map:
		// Map elements are not addressable: rewrite string values by key.
		if v.Type().Elem().Kind() != reflect.String {
			return
		}
		for _, k := range v.MapKeys() {
			v.SetMapIndex(k, reflect.ValueOf(visible(v.MapIndex(k).String(), false)).Convert(v.Type().Elem()))
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(visible(v.String(), multiline))
		}
	}
}

// jsonForTerminal rewrites the characters a terminal obeys and JSON does not
// escape — C1 controls, the bidirectional controls, DEL — as \u escapes. Inside
// JSON they can only occur in a string, where the escape means the same
// character: the document a program parses is unchanged, and the one a human
// reads in a terminal is inert. (encoding/json already escapes C0.)
//
// A carriage return is the exception, and the reason is JSON's own grammar: it
// is legal whitespace *between* tokens, where an escape is not legal at all, so
// it cannot be rewritten that way — and a terminal obeys it, returning the
// cursor to the start of the line, which lets an upstream document overwrite
// what has already been printed. Between tokens whitespace carries no meaning,
// so a CRLF loses the CR and a lone CR becomes a newline: the document a parser
// sees is the same one, and nothing reaches the terminal that it obeys. Inside a
// string a raw CR is not valid JSON in the first place.
func jsonForTerminal(doc []byte) []byte {
	var out bytes.Buffer
	for len(doc) > 0 {
		r, size := utf8.DecodeRune(doc)
		switch {
		case r == utf8.RuneError && size == 1:
			out.WriteString(`\ufffd`)
		case r == '\n' || r == '\t':
			// JSON's own layout between tokens; inside a string encoding/json
			// has already escaped them.
			out.Write(doc[:size])
		case r == '\r':
			// Insignificant whitespace that a terminal obeys (see above). CRLF
			// keeps just the newline; a lone CR becomes one.
			if len(doc) > size && doc[size] == '\n' {
				break
			}
			out.WriteByte('\n')
		case termsafe.Obeyed(r):
			// C1, DEL and the bidi controls are what JSON leaves unescaped; a
			// raw C0 is not valid inside a JSON string and harmless outside
			// one, and a body that carries it anyway is shown, not obeyed.
			fmt.Fprintf(&out, `\u%04x`, r)
		default:
			out.Write(doc[:size])
		}
		doc = doc[size:]
	}
	return out.Bytes()
}
