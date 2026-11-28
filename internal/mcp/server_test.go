package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/mcp/client"
	"github.com/nlink-jp/mcptool"
	"github.com/nlink-jp/mcptool/tooltest"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/config"
	"github.com/nlink-jp/shodan-lookup/internal/engine"
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

// build returns a function that serves s, for mcptool's tooltest (a server is
// served once, so each open builds a fresh one over the same tools).
func build(s *Server) tooltest.NewServer {
	return func(t testing.TB) *mcptool.Server {
		t.Helper()
		ms, err := s.Build()
		if err != nil {
			t.Fatal(err)
		}
		return ms
	}
}

// open serves s over pipes and opens it with nlink-jp/mcp's client, the way a
// dual-era MCP client does. Nothing here writes the handshake by hand.
func open(t *testing.T, s *Server) *client.Client {
	t.Helper()
	return tooltest.Open(t, build(s))
}

// openWith is open with the client's options (CancelNotice, say).
func openWith(t *testing.T, s *Server, opts client.Options) *client.Client {
	t.Helper()
	return tooltest.OpenWith(t, build(s), opts)
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

// toolErr runs one tool that must fail and returns its structured error.
func toolErr(t *testing.T, cl *client.Client, tool, args string) *mcptool.Error {
	t.Helper()
	res, err := callErr(cl, tool, args)
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	e, ok := tooltest.ToolError(res)
	if !ok {
		t.Fatalf("%s %s: not a structured tool error: %+v", tool, args, res)
	}
	return e
}

// wantArgErr runs one call that must be refused for the argument arg, with
// code. Codes are compared whole: invalid_arguments contains the CLI's
// invalid_argument, so a substring test would pass either.
func wantArgErr(t *testing.T, cl *client.Client, tool, args, code, arg string) {
	t.Helper()
	e := toolErr(t, cl, tool, args)
	if e.Code != code || e.Details["argument"] != arg {
		t.Errorf("%s %s: code %q, details %v (%s); want %q naming %q", tool, args, e.Code, e.Details, e.Message, code, arg)
	}
}

// ADR-030 §7: the server against the three probe clients.
func TestAgainstTheProbeClients(t *testing.T) {
	tooltest.ProbeMatrix(t, build(testServer(t)))
}

// ADR-021 §10: no tool returns a path that needs work_dir, and no schema or
// description holds a retired spelling. (Closed schemas, and schemas naming
// exactly their argument structs, are checked when the tools are registered.)
func TestTheSchemaContract(t *testing.T) {
	ms, err := testServer(t).Build()
	if err != nil {
		t.Fatal(err)
	}
	tooltest.SchemaContract(t, ms, tooltest.Contract{})
	if len(ms.Tools()) != len(toolDefinitions()) {
		t.Errorf("registered %d tools of %d", len(ms.Tools()), len(toolDefinitions()))
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
	cl := open(t, testServer(t))
	for tool, args := range map[string]string{
		ToolCacheStatus: `{"verbose":true}`,
		ToolGetQuota:    `{"verbose":true}`,
		ToolGetUsage:    `{"verbose":true}`,
		ToolLookupHost:  `{"ip":"192.0.2.1","verbose":true}`,
	} {
		wantArgErr(t, cl, tool, args, mcptool.CodeInvalidArguments, "verbose")
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

// An error nothing classified must not be reported as the caller's fault;
// the engine's codes pass through, its invalid_argument as invalid_arguments
// naming the argument (ADR-0002).
func TestToolErrorClassifies(t *testing.T) {
	for _, c := range []struct {
		err       error
		code, arg string
		msg       string
	}{
		{errors.New("disk on fire"), mcptool.CodeInternal, "", "disk on fire"},
		{&engine.Error{Code: engine.CodeNotIndexed, Message: "not in the index"}, engine.CodeNotIndexed, "", "not in the index"},
		{&engine.Error{Code: engine.CodeInvalidArgument, Message: "bad query", Argument: "query"}, mcptool.CodeInvalidArguments, "query", "bad query"},
		{invalidArg("ports", "too many"), mcptool.CodeInvalidArguments, "ports", "too many"},
	} {
		var e *mcptool.Error
		if !errors.As(toolError(c.err), &e) || e.Code != c.code || e.Message != c.msg {
			t.Errorf("%v: got %+v, want %s", c.err, e, c.code)
			continue
		}
		if got, _ := e.Details["argument"].(string); got != c.arg {
			t.Errorf("%v: argument %q, want %q", c.err, got, c.arg)
		}
	}
}

// An engine refusal reaches the agent as invalid_arguments, naming the
// argument the engine said it is about.
func TestAnEngineRefusalNamesItsArgument(t *testing.T) {
	s := lookupServer(t, &fakeEngine{err: &engine.Error{Code: engine.CodeInvalidArgument, Message: "10.0.0.1 is a private address", Argument: "ip"}})
	wantArgErr(t, open(t, s), ToolLookupHost, `{"ip":"10.0.0.1"}`, mcptool.CodeInvalidArguments, "ip")
}

// encoding/json matches names case-insensitively; the schema does not. An
// argument spelt in another case is refused by name, as an undeclared one is.
func TestAnArgumentInAnotherCaseIsRefused(t *testing.T) {
	cl := open(t, testServer(t))
	for args, name := range map[string]string{`{"IP":"192.0.2.1"}`: "IP", `{"ip":"192.0.2.1","Ports":[443]}`: "Ports"} {
		wantArgErr(t, cl, ToolLookupHost, args, mcptool.CodeInvalidArguments, name)
	}
}

// waitingEngine answers lookup_host only when its ctx is cancelled, and says
// so: it stands in for an upstream call still in flight.
type waitingEngine struct {
	fakeEngine
	cancelled chan error
}

func (w *waitingEngine) LookupHost(ctx context.Context, _ string, _ bool) (*engine.Host, error) {
	select {
	case <-ctx.Done():
		w.cancelled <- ctx.Err()
		return nil, ctx.Err()
	case <-time.After(5 * time.Second):
		w.cancelled <- nil
		return nil, errors.New("not cancelled")
	}
}

// notifications/cancelled reaches the engine as a cancelled ctx (ADR-0001
// §5): a client that gives up stops the upstream call. Detaching the
// handlers' ctx from the call would let it run on, and fails here.
func TestACancelledCallCancelsTheEngine(t *testing.T) {
	eng := &waitingEngine{cancelled: make(chan error, 1)}
	s := testServer(t)
	s.Eng = eng
	cl := openWith(t, s, client.Options{CancelNotice: true})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := cl.CallTool(ctx, ToolLookupHost, json.RawMessage(`{"ip":"192.0.2.1"}`), nil); err == nil {
		t.Fatal("the cancelled call returned a result")
	}
	select {
	case err := <-eng.cancelled:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("the engine's ctx ended with %v, want context.Canceled", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("the engine never returned")
	}
}

// The listing keeps toolDefinitions' order.
func TestToolsListKeepsTheDefinitionOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list, err := open(t, testServer(t)).ListTools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var want, got []string
	for _, def := range toolDefinitions() {
		name, _ := def["name"].(string)
		want = append(want, name)
	}
	for _, tl := range list.Tools {
		got = append(got, tl.Name)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("tools/list order = %v, want %v", got, want)
	}
}
