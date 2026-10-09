package mcp

import (
	"strings"
	"testing"
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
	if len([]rune(p.Title)) != fieldClip+1 || !strings.HasSuffix(p.Title, "…") {
		t.Errorf("title not shortened to %d runes plus a mark: %d", fieldClip, len([]rune(p.Title)))
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

// Nothing over the ceiling leaves, whatever it holds.
func TestToolTextWithholdsAnOversizedResult(t *testing.T) {
	big := map[string]any{"rows": make([]string, 0)}
	rows := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		rows = append(rows, strings.Repeat("y", 900))
	}
	big["rows"] = rows
	res := toolText(big)
	if res["isError"] != true {
		t.Fatal("a result over the ceiling was returned")
	}
	content := res["content"].([]map[string]any)
	if text, _ := content[0]["text"].(string); !strings.Contains(text, CodeTooLarge) {
		t.Errorf("the refusal does not carry %s: %s", CodeTooLarge, text)
	}
}
