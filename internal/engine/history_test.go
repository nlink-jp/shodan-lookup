package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nlink-jp/shodan-lookup/internal/shodan"
)

// historyBody builds a synthetic history (shapes as measured, values
// invented): a chatty 53/udp, and a 443/tcp whose certificate and title
// change halfway through.
func historyBody(chatty int) string {
	var data []any
	for i := 0; i < chatty; i++ {
		data = append(data, map[string]any{"port": 53, "transport": "udp", "_shodan": map[string]any{"module": "dns-udp"},
			"timestamp": fmt.Sprintf("2026-10-0%dT%02d:%02d:00.000000", 7+i/600, (i/60)%10, i%60), "data": "\nRecursion: enabled"})
	}
	for i, v := range []struct{ ts, title, sha1, product string }{
		{"2026-10-07T01:00:00.000000", "Old", "aaaa", "ExampleServer"},
		{"2026-10-07T02:00:00.000000", "Old", "aaaa", "ExampleServer"},
		{"2026-10-08T01:00:00.000000", "New", "bbbb", "ExampleServer"},
		{"2026-10-09T01:00:00.000000", "New", "bbbb", "ExampleServer"},
	} {
		data = append(data, map[string]any{"port": 443, "transport": "tcp", "timestamp": v.ts, "product": v.product,
			"data": fmt.Sprintf("HTTP/1.1 200 OK\r\nX-Seq: %d\r\n", i), "_shodan": map[string]any{"module": "https"},
			"http": map[string]any{"title": v.title},
			"ssl":  map[string]any{"cert": map[string]any{"fingerprint": map[string]any{"sha1": v.sha1}}}})
	}
	b, _ := json.Marshal(map[string]any{"ip_str": "1.2.3.4", "ports": []int{53, 443}, "data": data})
	return string(b)
}

func TestHistorySummarisesChangesOverAStatedWindow(t *testing.T) {
	up := newFake()
	up.histories["1.2.3.4"] = historyBody(HistoryCap - 4) // 996 + 4 = the cap
	h, err := testEngine(t, up).GetHistory(context.Background(), HistoryQuery{IP: "1.2.3.4"}, false)
	if err != nil {
		t.Fatal(err)
	}
	w := h.Window
	if w.Banners != HistoryCap || !w.Capped || w.Oldest != "2026-10-07T00:00:00Z" || w.Newest != "2026-10-09T01:00:00Z" {
		t.Errorf("window: %+v", w)
	}
	if w.Dominant == nil || w.Dominant.Port != 53 || w.Dominant.Banners != HistoryCap-4 {
		t.Errorf("the dominating port is not named: %+v", w.Dominant)
	}
	notes := strings.Join(h.Notes, " ")
	if !strings.Contains(notes, "nothing earlier can be read") || !strings.Contains(notes, "53/udp holds") {
		t.Errorf("notes: %v", h.Notes)
	}
	if len(h.Ports) != 2 || h.Ports[0].Port != 53 || h.Ports[1].Port != 443 {
		t.Fatalf("ports: %+v", h.Ports)
	}
	https := h.Ports[1]
	if https.Observations != 4 || https.FirstSeen != "2026-10-07T01:00:00Z" || https.LastSeen != "2026-10-09T01:00:00Z" || https.VariantCount != 2 {
		t.Errorf("443: %+v", https)
	}
	v0, v1 := https.Variants[0], https.Variants[1]
	if v0.Title != "Old" || v0.CertSHA1 != "aaaa" || v0.Observations != 2 || v0.LastSeen != "2026-10-07T02:00:00Z" ||
		v1.Title != "New" || v1.CertSHA1 != "bbbb" || v1.FirstSeen != "2026-10-08T01:00:00Z" {
		t.Errorf("variants are not the changes, in order: %+v", https.Variants)
	}
}

// Half the banners on one port is a fact; "the window is short because of
// it" is only true when the cap cut the window.
func TestADominantPortShortensOnlyACappedWindow(t *testing.T) {
	up := newFake()
	up.histories["1.2.3.4"] = historyBody(300) // 304 banners, under the cap
	h, err := testEngine(t, up).GetHistory(context.Background(), HistoryQuery{IP: "1.2.3.4"}, false)
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(h.Notes, " ")
	if h.Window.Dominant == nil || strings.Contains(notes, "short because") || !strings.Contains(notes, "53/udp holds 300") {
		t.Errorf("dominant %+v, notes %v", h.Window.Dominant, h.Notes)
	}
}

func TestHistoryUnderTheCapDoesNotClaimCompleteness(t *testing.T) {
	up := newFake()
	up.histories["1.2.3.4"] = historyBody(0)
	h, err := testEngine(t, up).GetHistory(context.Background(), HistoryQuery{IP: "1.2.3.4"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if h.Window.Capped || h.Window.Dominant != nil {
		t.Errorf("window: %+v", h.Window)
	}
	if !strings.Contains(strings.Join(h.Notes, " "), "not documented") {
		t.Errorf("an uncapped history is presented as complete: %v", h.Notes)
	}
}

func TestHistoryObservationsPage(t *testing.T) {
	up := newFake()
	up.histories["1.2.3.4"] = historyBody(10)
	e := testEngine(t, up)
	h, err := e.GetHistory(context.Background(), HistoryQuery{IP: "1.2.3.4", Port: 443, Limit: 3}, false)
	if err != nil {
		t.Fatal(err)
	}
	p := h.Port
	if p == nil || p.Total != 4 || len(p.Items) != 3 || p.NextOffset == nil || *p.NextOffset != 3 {
		t.Fatalf("page: %+v", p)
	}
	if p.Items[0].Timestamp != "2026-10-09T01:00:00Z" || p.Items[0].FirstLine != "HTTP/1.1 200 OK" || p.Items[0].CertSHA1 != "bbbb" {
		t.Errorf("newest first, as a line: %+v", p.Items[0])
	}
	dns, _ := e.GetHistory(context.Background(), HistoryQuery{IP: "1.2.3.4", Port: 53}, false)
	if dns.Port.Items[0].FirstLine != "Recursion: enabled" {
		t.Errorf("a DNS banner's first line: %q", dns.Port.Items[0].FirstLine)
	}
	_, err = e.GetHistory(context.Background(), HistoryQuery{IP: "1.2.3.4", Port: 8080}, false)
	wantCode(t, err, CodeNotObserved)
	if !strings.Contains(err.Error(), "not evidence that the port was closed") || !strings.Contains(err.Error(), "between 2026-10-07") {
		t.Errorf("message: %v", err)
	}
	for _, q := range []HistoryQuery{
		{IP: "1.2.3.4", Port: 443, Offset: 9},
		{IP: "1.2.3.4", Port: 443, Limit: MaxListLimit + 1},
		{IP: "1.2.3.4", Port: 443, Transport: "sctp"},
		{IP: "1.2.3.4", Port: -1},
		{IP: "10.0.0.1"},
	} {
		_, err := e.GetHistory(context.Background(), q, false)
		wantCode(t, err, CodeInvalidArgument)
	}
	if up.count("history") != 1 {
		t.Errorf("paging refetched the history: %d calls", up.count("history"))
	}
}

// A history 404 is cross-checked; services in a count make it an upstream
// failure that points at the current record, never "not indexed".
func TestHistory404IsCrossChecked(t *testing.T) {
	up := newFake()
	up.totals["ip:5.6.7.8"] = 15
	e := testEngine(t, up)
	_, err := e.GetHistory(context.Background(), HistoryQuery{IP: "5.6.7.8"}, false)
	wantCode(t, err, shodan.CodeUpstream)
	if !strings.Contains(err.Error(), "did not return its history") || !strings.Contains(err.Error(), "lookup_host") {
		t.Errorf("message: %v", err)
	}
	up.totals["ip:5.6.7.8"] = 0
	_, err = e.GetHistory(context.Background(), HistoryQuery{IP: "5.6.7.8"}, false)
	wantCode(t, err, CodeNotIndexed)
	// A count reads the current index; it cannot vouch for the past.
	if strings.Contains(err.Error(), "has not observed it") || !strings.Contains(err.Error(), "cannot be told") {
		t.Errorf("history not_indexed claims too much: %v", err)
	}
}
