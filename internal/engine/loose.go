package engine

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Shodan does not hold its fields to one type (measured: asn as 2497 and as
// "AS2497" within one record). Decoded strictly, one such value failed the
// whole document — a host record, a history window of 1,000 banners, a page
// that was paid for — and --raw with it, since the same decode gated the
// cache. decodeLoose reads a document one field at a time instead, and one
// array element at a time: a value this tool cannot read is left at its zero
// value, dropped from its list, and counted under its path.
//
// Paths are spelled from the wire types' own JSON names ("data[].http.status",
// "data[].vulns{}.cvss"); map keys and values never enter them, so they carry
// no third-party text, and the set of them is bounded by the types.

// skipped counts the values left out, by path.
type skipped map[string]int

// decodeLoose decodes the JSON object data into the struct v points to. Only
// a document that is not a JSON object is an error.
func decodeLoose(data []byte, v any) (skipped, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("not a JSON object")
	}
	sk := skipped{}
	looseFields(obj, reflect.ValueOf(v).Elem(), "", sk)
	return sk, nil
}

// note says what was left out, or "" when nothing was. what names the
// document's raw form, for where the values can still be read.
func (sk skipped) note(what string) string {
	if len(sk) == 0 {
		return ""
	}
	paths := make([]string, 0, len(sk))
	n := 0
	for p, c := range sk {
		paths = append(paths, fmt.Sprintf("%s (%d)", p, c))
		n += c
	}
	sort.Strings(paths)
	return fmt.Sprintf("%d value(s) in Shodan's document were of a type this tool does not read and are left out: %s — %s holds them as Shodan sent them",
		n, strings.Join(paths, ", "), what)
}

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// looseValue decodes raw into rv and reports whether it was read. A struct
// is read field by field and always counts as read; a leaf that fails is
// reset to its zero value and counted.
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
		elem := reflect.New(t.Elem())
		if !looseValue(raw, elem.Elem(), path, sk) {
			return false
		}
		rv.Set(elem)
		return true
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil || obj == nil {
			if isNull {
				return true
			}
			return miss(rv, path, sk)
		}
		looseFields(obj, rv, path, sk)
		return true
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
		for _, item := range items {
			elem := reflect.New(t.Elem()).Elem()
			if looseValue(item, elem, path+"[]", sk) {
				out = reflect.Append(out, elem)
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
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			return miss(rv, path, sk)
		}
		out := reflect.MakeMapWithSize(t, len(obj))
		for k, item := range obj {
			elem := reflect.New(t.Elem()).Elem()
			if looseValue(item, elem, path+"{}", sk) {
				out.SetMapIndex(reflect.ValueOf(k).Convert(t.Key()), elem)
			}
		}
		rv.Set(out)
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
	sk[path]++
	return false
}

// looseFields decodes the members of obj into the struct rv, matching names
// as encoding/json does: the tag's name, or the field's name without regard
// to case. An embedded struct without a tag reads the same object.
func looseFields(obj map[string]json.RawMessage, rv reflect.Value, path string, sk skipped) {
	t := rv.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct {
			looseFields(obj, rv.Field(i), path, sk)
			continue
		}
		if !f.IsExported() {
			continue
		}
		raw, key, ok := member(obj, name, f.Name)
		if !ok {
			continue
		}
		looseValue(raw, rv.Field(i), join(path, key), sk)
	}
}

// member finds a field's value, the exact name first and then without regard
// to case, as encoding/json does. The path names the field by its own name,
// never by the key Shodan sent.
func member(obj map[string]json.RawMessage, tag, field string) (json.RawMessage, string, bool) {
	name := tag
	if name == "" {
		name = field
	}
	key := tag
	if key == "" {
		key = strings.ToLower(field)
	}
	if raw, ok := obj[name]; ok {
		return raw, key, true
	}
	for k, raw := range obj {
		if strings.EqualFold(k, name) {
			return raw, key, true
		}
	}
	return nil, "", false
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}
