package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
)

// Shodan does not hold its fields to one type (measured: asn as 2497 and as
// "AS2497" within one record). Decoded strictly, one such value failed the
// whole document — a host record, a history window of 1,000 banners, a page
// that was paid for — and --raw with it, since the same decode gated the
// cache. decodeLoose reads a document one field at a time instead, and one
// list element at a time.
//
// What it cannot read must not turn into a value: a zero port, count or flag
// would read as a fact. So:
//   - a field it cannot read stays absent — the wire types make such fields
//     pointers, or a string whose empty value the projection does not show;
//   - a list element whose identifying field (tagged loose:"required": a
//     service's port, a facet value's count) is missing, null or cannot be
//     read is left out whole, never kept with a zero in that field — and so
//     is a list element that is null or not an object at all;
//   - a map entry is always kept, since its key is what names it (a CVE ID):
//     only the value's unreadable parts are absent.
//
// Every value left out is counted under its path, spelled from the wire
// types' own JSON names ("data[].http.status", "data[].vulns{}.cvss"); map
// keys and values never enter a path, so a note carries no third-party text,
// and the set of paths is bounded by the types.

// skipped counts what decoding left out, by path.
type skipped struct {
	values  map[string]int // values left absent
	entries map[string]int // why list elements were left out: the identifying field's path, or the element's own
	lists   map[string]int // how many elements each list lost ("data[]")
}

// decodeLoose decodes the JSON object data into the struct v points to. Only
// a document that is not a JSON object is an error.
func decodeLoose(data []byte, v any) (skipped, error) {
	members, ok := objectMembers(data)
	if !ok {
		return skipped{}, fmt.Errorf("not a JSON object")
	}
	sk := skipped{values: map[string]int{}, entries: map[string]int{}, lists: map[string]int{}}
	looseFields(members, reflect.ValueOf(v).Elem(), "", sk)
	return sk, nil
}

// dropped reports how many elements the list at path ("data[]") lost.
func (sk skipped) dropped(path string) int { return sk.lists[path] }

// note says what was left out, or "" when nothing was. raw names where the
// document can be read as Shodan sent it.
func (sk skipped) note(raw string) string {
	if len(sk.values) == 0 && len(sk.entries) == 0 {
		return ""
	}
	var parts []string
	if len(sk.values) > 0 {
		parts = append(parts, "left out: "+countList(sk.values))
	}
	if len(sk.entries) > 0 {
		parts = append(parts, "entries left out whole, counted by the reason — the field that identifies them, or the entry itself, missing or unreadable (one entry can count under two fields): "+countList(sk.entries))
	}
	return fmt.Sprintf("Shodan's document held values of a type this tool does not read — %s. Read each as unknown, not as zero, false or empty; %s holds them as Shodan sent them",
		strings.Join(parts, "; "), raw)
}

func countList(m map[string]int) string {
	out := make([]string, 0, len(m))
	for p, n := range m {
		out = append(out, fmt.Sprintf("%s (%d)", p, n))
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

type member struct {
	key string
	raw json.RawMessage
}

// objectMembers splits a JSON object into its members, in document order —
// the order encoding/json resolves duplicate and case-folded keys by.
func objectMembers(data []byte) ([]member, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var out []member
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, _ := tok.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		out = append(out, member{key, raw})
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, false // trailing data, valid or not
	}
	return out, true
}

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// looseValue decodes raw into rv and reports whether it was read. A struct
// is read field by field; it counts as read unless a required field could
// not be. A leaf that fails is reset to its zero value and counted.
func looseValue(raw json.RawMessage, rv reflect.Value, path string, sk skipped) bool {
	t := rv.Type()
	isNull := string(raw) == "null"
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		return looseLeaf(raw, rv, path, sk)
	}
	switch t.Kind() {
	case reflect.Pointer:
		if isNull {
			rv.SetZero()
			return true
		}
		if t.Elem().Kind() != reflect.Struct || reflect.PointerTo(t.Elem()).Implements(unmarshalerType) {
			return looseLeaf(raw, rv, path, sk)
		}
		elem := rv
		if rv.IsNil() {
			elem = reflect.New(t.Elem())
		}
		if !looseValue(raw, elem.Elem(), path, sk) {
			return false
		}
		rv.Set(elem)
		return true
	case reflect.Struct:
		if isNull {
			return true
		}
		members, ok := objectMembers(raw)
		if !ok {
			return miss(rv, path, sk)
		}
		return looseFields(members, rv, path, sk)
	case reflect.Slice:
		if isNull {
			rv.SetZero()
			return true
		}
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return miss(rv, path, sk)
		}
		out := reflect.MakeSlice(t, 0, len(items))
		elemPath := path + "[]"
		entries := t.Elem().Kind() == reflect.Struct
		for _, item := range items {
			elem := reflect.New(t.Elem()).Elem()
			switch {
			case entries && string(item) == "null":
				// encoding/json would keep a zero entry: a service on port 0.
				sk.entries[elemPath]++
				sk.lists[elemPath]++
			case looseValue(item, elem, elemPath, sk):
				out = reflect.Append(out, elem)
			case entries:
				// Not an object, or a required field failed: the entry is
				// left out whole and counted as an entry, not a value.
				if sk.values[elemPath] > 0 {
					uncount(sk.values, elemPath)
					sk.entries[elemPath]++
				}
				sk.lists[elemPath]++
			}
		}
		rv.Set(out)
		return true
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return looseLeaf(raw, rv, path, sk)
		}
		if isNull {
			rv.SetZero()
			return true
		}
		members, ok := objectMembers(raw)
		if !ok {
			return miss(rv, path, sk)
		}
		if rv.IsNil() {
			rv.Set(reflect.MakeMapWithSize(t, len(members)))
		}
		for _, m := range members {
			// The key names the entry: it is kept even when the value is not
			// read, and only the value's unreadable parts are absent.
			elem := reflect.New(t.Elem()).Elem()
			looseValue(m.raw, elem, path+"{}", sk)
			rv.SetMapIndex(reflect.ValueOf(m.key).Convert(t.Key()), elem)
		}
		return true
	}
	return looseLeaf(raw, rv, path, sk)
}

func looseLeaf(raw json.RawMessage, rv reflect.Value, path string, sk skipped) bool {
	if json.Unmarshal(raw, rv.Addr().Interface()) != nil {
		return miss(rv, path, sk)
	}
	return true
}

func miss(rv reflect.Value, path string, sk skipped) bool {
	rv.SetZero()
	sk.values[path]++
	return false
}

func uncount(m map[string]int, path string) {
	if m[path]--; m[path] <= 0 {
		delete(m, path)
	}
}

// looseFields decodes members into the struct rv as encoding/json does: in
// document order, each member to the field whose name matches exactly or else
// without regard to case, a later member overriding an earlier one. An
// embedded struct without a tag takes its fields from the same object.
//
// It reports false when a required field is missing, null, or unreadable in
// its last occurrence (an earlier unreadable duplicate is overridden, as in
// encoding/json); the field's path is then counted as the reason its entry
// was left out, not as a value. A required field must be a leaf — a string or
// a number — so that one path accounts for it.
func looseFields(members []member, rv reflect.Value, path string, sk skipped) bool {
	fields := structFields(rv)
	read := map[int]bool{} // required fields: last occurrence read
	for _, m := range members {
		i, found := matchField(fields, m.key)
		if !found {
			continue
		}
		f, p := fields[i], join(path, fields[i].name)
		if !f.required {
			looseValue(m.raw, f.v, p, sk)
			continue
		}
		if string(m.raw) == "null" {
			f.v.SetZero()
			read[i] = false
			continue
		}
		read[i] = looseValue(m.raw, f.v, p, sk)
		if !read[i] {
			uncount(sk.values, p)
		}
	}
	ok := true
	for i, f := range fields {
		if f.required && !read[i] {
			sk.entries[join(path, f.name)]++
			ok = false
		}
	}
	return ok
}

type field struct {
	name     string // the JSON name, or the Go name in lower case
	exact    string // what a key must equal to match exactly
	v        reflect.Value
	required bool
}

func structFields(rv reflect.Value) []field {
	var out []field
	t := rv.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct {
			out = append(out, structFields(rv.Field(i))...)
			continue
		}
		if !f.IsExported() {
			continue
		}
		exact := name
		if exact == "" {
			exact, name = f.Name, strings.ToLower(f.Name)
		}
		out = append(out, field{name: name, exact: exact, v: rv.Field(i), required: f.Tag.Get("loose") == "required"})
	}
	return out
}

func matchField(fields []field, key string) (int, bool) {
	for i, f := range fields {
		if f.exact == key {
			return i, true
		}
	}
	for i, f := range fields {
		if strings.EqualFold(f.exact, key) {
			return i, true
		}
	}
	return 0, false
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}
