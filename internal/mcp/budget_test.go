package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/nlink-jp/mcptool"
)

// The backstop shortens any ungoverned string and names it, and never touches
// a page of text a section returned — that page exists to be whole.
func TestCapStringsShortensOnlyUngovernedText(t *testing.T) {
	long := strings.Repeat("x", fieldClip+5)
	type page struct {
		Title string   `json:"title"`
		Text  string   `json:"text"`
		Notes []string `json:"notes,omitempty"`
	}
	got, names := capStrings(&page{Title: long, Text: long})
	p := got.(*page)
	if len([]rune(p.Title)) != fieldClip || !strings.HasSuffix(p.Title, "…") {
		t.Errorf("title not shortened to %d runes, the mark included: %d", fieldClip, len([]rune(p.Title)))
	}
	if p.Text != long {
		t.Error("a section's page of text was shortened")
	}
	if len(names) != 1 || names[0] != "title" {
		t.Errorf("shortened fields = %v, want [title]", names)
	}
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "title") {
		t.Errorf("the result does not say what was shortened: %v", p.Notes)
	}

	m, names := capStrings(map[string]any{"banner": long, "text": long})
	mm := m.(map[string]any)
	if mm["text"] != long || len(names) != 1 || names[0] != "banner" {
		t.Errorf("map result: shortened %v; text kept whole = %v", names, mm["text"] == long)
	}
}

// A result goes through the backstop twice — inside a tool, so thinning
// measures what will be sent, and again at the ceiling. The second pass must
// find nothing to do: a shortened string is not shortened again, and the note
// saying so is written once.
func TestCapStringsTwiceShortensAndNotesOnce(t *testing.T) {
	type page struct {
		Title string   `json:"title"`
		Notes []string `json:"notes,omitempty"`
	}
	p := &page{Title: strings.Repeat("x", fieldClip+5)}
	capStrings(p)
	once := p.Title
	if _, names := capStrings(p); len(names) != 0 || p.Title != once {
		t.Errorf("the second pass shortened %v again: %d runes", names, len([]rune(p.Title)))
	}
	if len(p.Notes) != 1 {
		t.Errorf("notes = %d, want 1: %v", len(p.Notes), p.Notes)
	}
}

// Nothing over the ceiling leaves, whatever it holds.
func TestTheCeilingWithholdsAnOversizedResult(t *testing.T) {
	rows := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		rows = append(rows, strings.Repeat("y", 900))
	}
	out, err := withinCeiling(map[string]any{"rows": rows})
	var e *mcptool.Error
	if out != nil || !errors.As(err, &e) || e.Code != CodeTooLarge {
		t.Fatalf("a result over the ceiling was returned: out %v, err %v", out != nil, err)
	}
}

// The budget measures what is sent: one line, < > & as one byte each. A
// result of HTML-heavy text that fits only that way is returned, as the very
// bytes measured; measured indented or escaped, it would have been withheld.
func TestTheCeilingMeasuresWhatIsSent(t *testing.T) {
	rows := make([]string, 0, 160)
	for i := 0; i < 160; i++ {
		rows = append(rows, strings.Repeat("<&>", 270)) // 810 bytes sent, 4,860 escaped
	}
	v := map[string]any{"rows": rows}
	if b, _ := json.MarshalIndent(v, "", "  "); len(b) <= maxResultBytes {
		t.Fatalf("the fixture is %d bytes escaped and indented; it no longer tests the measure", len(b))
	}
	out, err := withinCeiling(v)
	if err != nil {
		t.Fatalf("withheld: %v", err)
	}
	want, _ := wire(v)
	if !reflect.DeepEqual(out, mcptool.Text(string(want))) {
		t.Error("the result is not the bytes measured")
	}
	if strings.Contains(string(want), `\u0026`) || bytes.Contains(want, []byte("\n")) {
		t.Errorf("wire escapes HTML or is not one line: %.80s", want)
	}
}
