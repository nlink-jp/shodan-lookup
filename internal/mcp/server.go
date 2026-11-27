package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/nlink-jp/mcp"
	mcpserver "github.com/nlink-jp/mcp/server"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/config"
)

// serverName is what initialize reports, and what a client lists the server as.
const serverName = "shodan-lookup"

// Server serves the engine as MCP tools over stdio. The protocol — both eras,
// framing, versions, cancellation — is nlink-jp/mcp's (organization ADR-030,
// ADR-0001); this type holds the tools.
type Server struct {
	Cfg     *config.Config
	Cache   *cache.Store
	Eng     Engine
	Version string
}

// Serve runs the server until stdin reaches EOF (answering every request that
// arrived), ctx is cancelled, or a write to stdout fails.
func (s *Server) Serve(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	if stdin == nil {
		return fmt.Errorf("no input stream: the MCP server reads JSON-RPC from stdin")
	}
	ts, err := s.toolServer()
	if err != nil {
		return err
	}
	return ts.Serve(ctx, stdin, stdout)
}

// toolServer registers toolDefinitions, in order, on a fresh protocol server;
// each handler calls callTool. One is built per Serve.
func (s *Server) toolServer() (*mcpserver.ToolServer, error) {
	ts, err := mcpserver.New(mcpserver.Info{
		Server:       mcp.Implementation{Name: serverName, Version: s.Version},
		Instructions: instructions,
	}, mcpserver.Options{
		// The engine's pacing and the search credit guard assume one call at
		// a time.
		Workers: 1,
		// Calls sent side by side wait, as they did before the module: the
		// default of 16 would refuse the 17th as "server busy".
		QueueDepth: 256,
		Logger:     slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		return nil, err
	}
	for _, def := range toolDefinitions() {
		schema, err := json.Marshal(def["inputSchema"])
		if err != nil {
			return nil, fmt.Errorf("tool %v: %w", def["name"], err)
		}
		name, okName := def["name"].(string)
		desc, okDesc := def["description"].(string)
		if !okName || !okDesc {
			return nil, fmt.Errorf("tool %v: name and description must be strings", def["name"])
		}
		if err := ts.AddTool(mcpserver.Tool{Name: name, Description: desc, InputSchema: schema}, s.handle); err != nil {
			return nil, err
		}
	}
	return ts, nil
}

// handle runs one tools/call: callTool builds the result, and it is copied
// into the protocol's shape. The protocol layer has already refused an unknown
// tool and arguments that are not an object.
func (s *Server) handle(ctx context.Context, req *mcpserver.Request) (*mcpserver.Result, error) {
	res := s.callTool(ctx, req.Name, req.Arguments)
	out := &mcpserver.Result{IsError: res["isError"] == true}
	// toolText, toolRawText and toolError build content as []map[string]any;
	// anything else is a programming error, not an empty success.
	blocks, ok := res["content"].([]map[string]any)
	if !ok {
		return nil, fmt.Errorf("tool %s: result content is %T", req.Name, res["content"])
	}
	for _, b := range blocks {
		raw, err := json.Marshal(b)
		if err != nil {
			return nil, err
		}
		out.Content = append(out.Content, raw)
	}
	return out, nil
}

// callTool runs one tool by name and wraps its result as tools/call content.
func (s *Server) callTool(ctx context.Context, name string, args json.RawMessage) map[string]any {
	result, err := s.dispatch(ctx, name, args)
	if err != nil {
		// Tool failures are results, not protocol errors: the model has to see
		// them and decide what to do, and a JSON-RPC error would be swallowed
		// by the client instead.
		return toolError(err)
	}
	// get_usage returns the manual itself, which is Markdown rather than a JSON
	// document — wrapping it in JSON would only make it harder to read. It is
	// told apart here, after dispatch, so that it goes through the same
	// argument check as every other tool.
	if doc, ok := result.(rawText); ok {
		return toolRawText(string(doc))
	}
	result, _ = capStrings(result)
	return toolText(result)
}

// rawText is a tool result that is already the text to return.
type rawText string

// maxResultBytes is the ceiling no tool result may cross, whatever a field
// turns out to hold. Every known large part gets its own cap and its own way to
// be read in full as the lookup tools land; this is for the part nobody thought
// of. One measured Shodan host record was 991 KB before projection.
const maxResultBytes = 128 << 10

// toolText wraps a payload as MCP text content. Structured data is returned as
// JSON text because that is what the content protocol carries.
func toolText(v any) map[string]any {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolError(fmt.Errorf("encode result: %w", err))
	}
	if len(b) > maxResultBytes {
		return toolError(&argError{code: CodeTooLarge, msg: fmt.Sprintf(
			"the result is %d bytes, over this server's ceiling of %d; ask for less — fewer ports, or one section at a time", len(b), maxResultBytes)})
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(b)}},
	}
}

func toolRawText(s string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": s}}}
}

func toolError(err error) map[string]any {
	b, mErr := json.Marshal(structuredError(err))
	text := string(b)
	if mErr != nil {
		text = `{"code":"internal_error","message":"could not encode the error"}`
	}
	return map[string]any{
		"isError": true,
		"content": []map[string]any{{"type": "text", "text": text}},
	}
}
