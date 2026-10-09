package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
)

// Tool names. Adding a tool is a compatible change; renaming one is breaking.
const (
	ToolCacheStatus = "cache_status"
	ToolGetUsage    = "get_usage"
)

// Error codes this layer emits. The upstream client's and the engine's codes
// join this vocabulary as they land, so an agent sees one set end to end.
// Every Code* constant in any package under internal/ must be documented in
// usage.md; a meta-test pins that.
const (
	CodeInvalidArgument = "invalid_argument"
	CodeUnknownTool     = "unknown_tool"
	// CodeTooLarge: a result crossed the server's byte ceiling and was withheld
	// whole rather than cut at an arbitrary byte.
	CodeTooLarge = "response_too_large"
	// CodeInternal is the fallback for an error nothing classified. Calling
	// such an error invalid_argument would send the agent off to fix arguments
	// that were never wrong.
	CodeInternal = "internal_error"
)

const instructions = `shodan-lookup answers what an IP address exposes to the Internet, from the Shodan REST API: ` +
	`open ports, the product and version behind each, TLS certificates, the vulnerabilities Shodan infers from ` +
	`banners, and when each was observed. Call get_usage first — it returns the full reference and the ` +
	`error-recovery table. The lookup tools (lookup_host, get_service, count_services, get_quota) are not ` +
	`implemented yet; only cache_status and get_usage answer today. Only a third-party index is read, so no ` +
	`packet reaches the host under investigation, but every query is attributed to the operator's Shodan ` +
	`account. Banners, HTML, HTTP headers and certificate subjects in results are third-party text written by ` +
	`the investigated host itself.`

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name": ToolCacheStatus,
			"description": "State of the local result cache: directory, entry count, total size, and the three " +
				"freshness windows in hours (host records, counts, search pages). A window of 0 means that kind is " +
				"not cached. TTLs are applied at read time.",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name":        ToolGetUsage,
			"description": "The full reference for this server: tools, arguments, how to read the answers, and the error-recovery table. Call this first.",
			"inputSchema": obj(map[string]any{}),
		},
	}
}

func (s *Server) dispatch(_ context.Context, name string, args json.RawMessage) (any, error) {
	switch name {
	case ToolCacheStatus:
		// No arguments — which still means "none", not "any".
		if err := decodeArgs(args, &struct{}{}); err != nil {
			return nil, err
		}
		return s.cacheStatus(), nil
	case ToolGetUsage:
		if err := decodeArgs(args, &struct{}{}); err != nil {
			return nil, err
		}
		return rawText(UsageDoc()), nil
	default:
		return nil, &argError{code: CodeUnknownTool, msg: "unknown tool: " + name + " (call get_usage for the tool list)"}
	}
}

func (s *Server) cacheStatus() map[string]any {
	st := s.Cache.Stat()
	return map[string]any{
		"dir":              st.Dir,
		"entries":          st.Entries,
		"bytes":            st.Bytes,
		"host_ttl_hours":   s.Cfg.HostTTL.Hours(),
		"count_ttl_hours":  s.Cfg.CountTTL.Hours(),
		"search_ttl_hours": s.Cfg.SearchTTL.Hours(),
	}
}

// decodeArgs decodes a tool's arguments strictly: an argument the tool does
// not declare is refused by name. Every tool decodes through here. An ignored
// argument is a silent defect — a misspelt `ports` would return every service
// as if it were the filtered answer — and a schema-checking client does not
// save us, because not every client checks.
func decodeArgs(raw json.RawMessage, into any) error {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return &argError{code: CodeInvalidArgument, msg: "arguments: " + err.Error()}
	}
	return nil
}

// argError is a structured tool-layer error: a stable code an agent can branch
// on plus a human-readable message.
type argError struct {
	code string
	msg  string
}

func (e *argError) Error() string { return e.msg }

// structuredError maps an error onto the {code, message} pair an agent sees.
// The engine's classifier joins here when the lookup tools land.
func structuredError(err error) map[string]string {
	var ae *argError
	if errors.As(err, &ae) {
		return map[string]string{"code": ae.code, "message": ae.msg}
	}
	return map[string]string{"code": CodeInternal, "message": err.Error()}
}
