package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/config"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		Cfg: &config.Config{
			HostTTL:   config.DefaultHostTTL,
			CountTTL:  config.DefaultCountTTL,
			SearchTTL: config.DefaultSearchTTL,
		},
		Cache:   &cache.Store{Dir: t.TempDir()},
		Version: "test",
	}
}

// serve feeds newline-delimited frames through the server and returns the
// decoded responses. This dummy JSON-RPC harness is what reaches the server-
// side validation paths a schema-checking client would never exercise.
func serve(t *testing.T, s *Server, frames ...string) []map[string]any {
	t.Helper()
	in := strings.NewReader(strings.Join(frames, "\n") + "\n")
	var out strings.Builder
	if err := s.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resps []map[string]any
	dec := json.NewDecoder(strings.NewReader(out.String()))
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode response: %v (raw: %s)", err, out.String())
		}
		resps = append(resps, m)
	}
	return resps
}

// toolResultText returns the text of a tools/call result's single content block.
func toolResultText(t *testing.T, resp map[string]any) (string, map[string]any) {
	t.Helper()
	result, _ := resp["result"].(map[string]any)
	if result == nil {
		t.Fatalf("no result (a protocol error?): %v", resp)
	}
	content, _ := result["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("content blocks = %d, want 1", len(content))
	}
	block, _ := content[0].(map[string]any)
	text, _ := block["text"].(string)
	return text, result
}

func TestInitializeIdentifiesTheServer(t *testing.T) {
	resps := serve(t, testServer(t), `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	result, _ := resps[0]["result"].(map[string]any)
	if result == nil {
		t.Fatalf("initialize returned no result: %v", resps[0])
	}
	if result["protocolVersion"] != protocolVersion {
		t.Errorf("protocolVersion = %v, want %s", result["protocolVersion"], protocolVersion)
	}
	info, _ := result["serverInfo"].(map[string]any)
	if info == nil || info["name"] != "shodan-lookup" {
		t.Errorf("serverInfo does not name the server: %v", result["serverInfo"])
	}
	if info != nil && info["version"] != "test" {
		t.Errorf("serverInfo.version = %v, want the injected version", info["version"])
	}
	s, _ := result["instructions"].(string)
	if !strings.Contains(s, "get_usage") {
		t.Error("instructions do not point the agent at get_usage")
	}
	// Banners are written by the investigated host; the agent is told that
	// fact before it ever sees one — and that its queries are attributed.
	if !strings.Contains(s, "attributed to the operator's Shodan account") {
		t.Error("instructions do not state that queries are attributed to the account")
	}
	if !strings.Contains(s, "third-party text") {
		t.Error("instructions do not state that result text is third-party")
	}
}

// Tool text states triggers, contracts and provenance. Telling the model how
// to defend itself is the runtime's layer, not a tool's: a "never …" written
// here over-generalises in the reader and adds nothing a runtime can enforce.
func TestToolTextCarriesNoDefensiveImperatives(t *testing.T) {
	texts := map[string]string{"instructions": instructions, "usage.md": UsageDoc()}
	for _, def := range toolDefinitions() {
		name, _ := def["name"].(string)
		desc, _ := def["description"].(string)
		texts["description of "+name] = desc
	}
	for where, text := range texts {
		lower := strings.ToLower(text)
		for _, phrase := range []string{"never as instructions", "treat them as data", "do not follow", "ignore any instruction"} {
			if strings.Contains(lower, phrase) {
				t.Errorf("%s carries a defensive imperative: %q", where, phrase)
			}
		}
	}
}

// An argument the tool does not declare is refused by name, even for a tool
// that takes none. Reached through the raw harness on purpose: a
// schema-checking client would never send this.
func TestUndeclaredArgumentsAreRefused(t *testing.T) {
	resps := serve(t, testServer(t),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cache_status","arguments":{"verbose":true}}}`)
	text, result := toolResultText(t, resps[0])
	if result["isError"] != true {
		t.Fatalf("an undeclared argument was accepted: %s", text)
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("tool error is not structured JSON: %s", text)
	}
	if payload["code"] != CodeInvalidArgument {
		t.Errorf("code = %q, want %q", payload["code"], CodeInvalidArgument)
	}
	if !strings.Contains(payload["message"], "verbose") {
		t.Errorf("the message does not name the argument: %q", payload["message"])
	}
}

// Absent, null and empty arguments all mean "none".
func TestNoArgumentsInEverySpelling(t *testing.T) {
	for _, params := range []string{
		`{"name":"cache_status"}`,
		`{"name":"cache_status","arguments":null}`,
		`{"name":"cache_status","arguments":{}}`,
	} {
		resps := serve(t, testServer(t), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+params+`}`)
		if _, result := toolResultText(t, resps[0]); result["isError"] == true {
			t.Errorf("%s: refused although it carries no arguments", params)
		}
	}
}

func TestMalformedFrameGetsParseError(t *testing.T) {
	resps := serve(t, testServer(t), `{not json`)
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	errObj, _ := resps[0]["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("no error object: %v", resps[0])
	}
	if code, _ := errObj["code"].(float64); int(code) != -32700 {
		t.Errorf("code = %v, want -32700", errObj["code"])
	}
}

func TestUnknownMethodIsMethodNotFound(t *testing.T) {
	resps := serve(t, testServer(t), `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)
	errObj, _ := resps[0]["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("no error object: %v", resps[0])
	}
	if code, _ := errObj["code"].(float64); int(code) != -32601 {
		t.Errorf("code = %v, want -32601", errObj["code"])
	}
}

// Notifications (no id) must not be answered — not even unknown ones.
func TestNotificationsAreNotAnswered(t *testing.T) {
	resps := serve(t, testServer(t),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled"}`,
		`{"jsonrpc":"2.0","method":"something/unknown"}`,
	)
	if len(resps) != 0 {
		t.Errorf("notifications were answered: %v", resps)
	}
}

func TestToolsListNamesEveryTool(t *testing.T) {
	resps := serve(t, testServer(t), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	result, _ := resps[0]["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	names := map[string]bool{}
	for _, tl := range tools {
		m, _ := tl.(map[string]any)
		if m == nil {
			t.Fatalf("tool entry is not an object: %v", tl)
		}
		name, _ := m["name"].(string)
		names[name] = true
		if _, ok := m["inputSchema"]; !ok {
			t.Errorf("tool %s has no inputSchema", name)
		}
	}
	for _, want := range []string{ToolCacheStatus, ToolGetUsage} {
		if !names[want] {
			t.Errorf("tools/list is missing %s (got %v)", want, names)
		}
	}
}

func TestGetUsageReturnsTheManual(t *testing.T) {
	resps := serve(t, testServer(t),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_usage"}}`)
	text, result := toolResultText(t, resps[0])
	if !strings.Contains(text, "cache_status") {
		t.Error("the manual does not document cache_status")
	}
	if result["isError"] == true {
		t.Error("get_usage reported an error")
	}
}

func TestCacheStatusReportsEveryTTL(t *testing.T) {
	resps := serve(t, testServer(t),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cache_status"}}`)
	text, _ := toolResultText(t, resps[0])

	var payload map[string]any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("cache_status did not return JSON: %v (raw: %s)", err, text)
	}
	for field, want := range map[string]float64{
		"host_ttl_hours":   config.DefaultHostTTL.Hours(),
		"count_ttl_hours":  config.DefaultCountTTL.Hours(),
		"search_ttl_hours": config.DefaultSearchTTL.Hours(),
	} {
		if payload[field] != want {
			t.Errorf("%s = %v, want %v", field, payload[field], want)
		}
	}
}

// An unknown tool is a tool result, not a protocol error: the model has to see
// it. The body is the structured {code, message} vocabulary.
func TestUnknownToolIsAStructuredToolError(t *testing.T) {
	resps := serve(t, testServer(t),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"no_such_tool"}}`)
	text, result := toolResultText(t, resps[0])
	if result["isError"] != true {
		t.Error("unknown tool did not set isError")
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("tool error is not structured JSON: %s", text)
	}
	if payload["code"] != CodeUnknownTool {
		t.Errorf("code = %q, want %q", payload["code"], CodeUnknownTool)
	}
}

// An error nothing classified must not be reported as the caller's fault.
func TestUnclassifiedErrorIsInternalNotInvalidArgument(t *testing.T) {
	got := structuredError(errors.New("disk on fire"))
	if got["code"] != CodeInternal {
		t.Errorf("code = %q, want %q", got["code"], CodeInternal)
	}
	if got["message"] != "disk on fire" {
		t.Errorf("message = %q", got["message"])
	}
}

func TestBlankLinesAreIgnored(t *testing.T) {
	resps := serve(t, testServer(t), "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "")
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	if resps[0]["error"] != nil {
		t.Errorf("ping failed: %v", resps[0])
	}
}
