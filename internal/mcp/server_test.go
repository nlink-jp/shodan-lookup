package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/mcp"
	"github.com/nlink-jp/mcp/client"
	"github.com/nlink-jp/mcp/probe"

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

// open serves s over pipes and opens it with nlink-jp/mcp's client, the way a
// dual-era MCP client does (server-migration §6). Nothing here writes the
// handshake by hand.
func open(t *testing.T, s *Server) *client.Client {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.Serve(ctx, inR, outW)
		_ = outW.Close()
	}()
	kill := func() { cancel(); _ = inW.Close(); _ = outR.Close() }
	conn, err := client.NewLineConn(outR, inW, kill, client.LineOptions{})
	if err != nil {
		t.Fatal(err)
	}
	octx, ocancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ocancel()
	cl, err := client.Open(octx, conn, client.Options{Client: mcp.Implementation{Name: "test", Version: "0"}})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		_ = cl.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after the client closed")
		}
		kill()
	})
	return cl
}

// callTool runs one tool. args is the arguments' JSON, or "" for none. It
// returns the single content block's text and the result.
func callTool(t *testing.T, cl *client.Client, tool, args string) (string, *client.ToolResult) {
	t.Helper()
	res, err := callErr(cl, tool, args)
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("content blocks = %d, want 1", len(res.Content))
	}
	var block struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(res.Content[0], &block); err != nil {
		t.Fatalf("%s: content: %v", tool, err)
	}
	return block.Text, res
}

func callErr(cl *client.Client, tool, args string) (*client.ToolResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var a any
	if args != "" {
		a = json.RawMessage(args)
	}
	return cl.CallTool(ctx, tool, a, nil)
}

// ADR-030 §7: the server against the three probe clients — legacy only,
// dual-era, modern only — with the outcomes the specification's
// compatibility matrix gives for a dual-era server.
func TestAgainstTheProbeClients(t *testing.T) {
	for _, kind := range []probe.ClientKind{probe.ClientLegacyOnly, probe.ClientDual, probe.ClientModernOnly} {
		s := testServer(t)
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = s.Serve(ctx, inR, outW); _ = outW.Close() }()
		r := probe.Run(ctx, kind, outR, inW, probe.ClientOptions{StepTimeout: 2 * time.Second})
		cancel()
		_ = inW.Close()
		if want := probe.Expect(kind, probe.ServerDual); r.Outcome != want || len(r.Violations) != 0 || len(r.Warnings) != 0 {
			t.Errorf("%v probe client: outcome %s (want %s), violations %v, warnings %v, error %s",
				kind, r.Outcome, want, r.Violations, r.Warnings, r.Error)
		}
	}
}

func TestServeRefusesANilInput(t *testing.T) {
	if err := testServer(t).Serve(context.Background(), nil, io.Discard); err == nil {
		t.Error("Serve accepted a nil stdin")
	}
}

func TestInitializeIdentifiesTheServer(t *testing.T) {
	cl := open(t, testServer(t))
	info := cl.Server()
	if info.Name != "shodan-lookup" {
		t.Errorf("serverInfo does not name the server: %+v", info)
	}
	if info.Version != "test" {
		t.Errorf("serverInfo.version = %q, want the injected version", info.Version)
	}
	s := cl.Instructions()
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
// that takes none. A schema-checking client would never send this; the
// module's client sends what it is given.
func TestUndeclaredArgumentsAreRefused(t *testing.T) {
	text, result := callTool(t, open(t, testServer(t)), "cache_status", `{"verbose":true}`)
	if !result.IsError {
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
	cl := open(t, testServer(t))
	for _, args := range []string{``, `null`, `{}`} {
		if _, result := callTool(t, cl, "cache_status", args); result.IsError {
			t.Errorf("arguments %q: refused although it carries no arguments", args)
		}
	}
}

func TestToolsListNamesEveryTool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list, err := open(t, testServer(t)).ListTools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tl := range list.Tools {
		names[tl.Name] = true
		if len(tl.InputSchema) == 0 {
			t.Errorf("tool %s has no inputSchema", tl.Name)
		}
	}
	for _, want := range []string{ToolCacheStatus, ToolGetUsage} {
		if !names[want] {
			t.Errorf("tools/list is missing %s (got %v)", want, names)
		}
	}
}

func TestGetUsageReturnsTheManual(t *testing.T) {
	text, result := callTool(t, open(t, testServer(t)), "get_usage", "")
	if !strings.Contains(text, "cache_status") {
		t.Error("the manual does not document cache_status")
	}
	if result.IsError {
		t.Error("get_usage reported an error")
	}
}

func TestCacheStatusReportsEveryTTL(t *testing.T) {
	text, _ := callTool(t, open(t, testServer(t)), "cache_status", "")

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

// An unknown tool never reaches a handler: the protocol layer refuses it with
// -32602 (server-migration §4), so it is not a tool result any more.
func TestUnknownToolIsAProtocolError(t *testing.T) {
	_, err := callErr(open(t, testServer(t)), "no_such_tool", "")
	var e *mcp.Error
	if !errors.As(err, &e) || e.Code != -32602 {
		t.Errorf("err = %v, want -32602", err)
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
