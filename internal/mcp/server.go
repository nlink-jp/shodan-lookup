package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/config"
)

// protocolVersion is the MCP revision this server speaks.
const protocolVersion = "2024-11-05"

// serverName is what initialize reports, and what a client lists the server as.
const serverName = "shodan-lookup"

// Server is a stdio JSON-RPC 2.0 MCP server.
type Server struct {
	Cfg     *config.Config
	Cache   *cache.Store
	Eng     Engine
	Version string
}

// Serve reads newline-delimited JSON-RPC messages until stdin closes, which is
// the shutdown signal.
func (s *Server) Serve(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	if stdin == nil {
		return fmt.Errorf("no input stream: the MCP server reads JSON-RPC from stdin")
	}
	sc := bufio.NewScanner(stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	enc := json.NewEncoder(stdout)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			// A malformed frame gets a parse error with a null id, per the
			// JSON-RPC spec. Staying silent would hang the client.
			if err := enc.Encode(errorResponse(nil, -32700, "parse error: "+err.Error())); err != nil {
				return err
			}
			continue
		}
		resp, ok := s.handle(ctx, &req)
		if !ok {
			continue // a notification: no reply
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func errorResponse(id json.RawMessage, code int, msg string) response {
	return response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func okResponse(id json.RawMessage, result any) response {
	return response{JSONRPC: "2.0", ID: id, Result: result}
}

// handle dispatches one message. The second return value is false for
// notifications, which must not be answered.
func (s *Server) handle(ctx context.Context, req *request) (response, bool) {
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"

	switch req.Method {
	case "initialize":
		return okResponse(req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "version": s.Version},
			"instructions":    instructions,
		}), true

	case "notifications/initialized", "notifications/cancelled":
		return response{}, false

	case "ping":
		return okResponse(req.ID, map[string]any{}), true

	case "tools/list":
		return okResponse(req.ID, map[string]any{"tools": toolDefinitions()}), true

	case "tools/call":
		if isNotification {
			return response{}, false
		}
		return s.callTool(ctx, req), true

	default:
		if isNotification {
			return response{}, false
		}
		return errorResponse(req.ID, -32601, "method not found: "+req.Method), true
	}
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) callTool(ctx context.Context, req *request) response {
	var p callParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errorResponse(req.ID, -32602, "invalid params: "+err.Error())
		}
	}
	result, err := s.dispatch(ctx, p.Name, p.Arguments)
	if err != nil {
		// Tool failures are results, not protocol errors: the model has to see
		// them and decide what to do, and a JSON-RPC error would be swallowed
		// by the client instead.
		return okResponse(req.ID, toolError(err))
	}
	// get_usage returns the manual itself, which is Markdown rather than a JSON
	// document — wrapping it in JSON would only make it harder to read. It is
	// told apart here, after dispatch, so that it goes through the same
	// argument check as every other tool.
	if doc, ok := result.(rawText); ok {
		return okResponse(req.ID, toolRawText(string(doc)))
	}
	result, _ = capStrings(result)
	return okResponse(req.ID, toolText(result))
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
