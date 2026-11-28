package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nlink-jp/mcptool"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/config"
	"github.com/nlink-jp/shodan-lookup/internal/engine"
)

// serverName is what initialize reports, and what a client lists the server as.
const serverName = "shodan-lookup"

// Server holds what the tools need. The protocol — both eras, framing,
// versions, cancellation — is nlink-jp/mcp's (organization ADR-030,
// ADR-0001); the tool conventions — argument decoding, structured errors,
// results, serving — are nlink-jp/mcptool's (organization ADR-031,
// ADR-0002). Build makes the server; mcptool/serve's Run serves it.
type Server struct {
	Cfg     *config.Config
	Cache   *cache.Store
	Eng     Engine
	Version string
}

// Build returns the MCP server, its tools registered in toolDefinitions'
// order. A server is served once, so each Serve needs its own Build.
//
// mcptool's defaults hold what this server asks for: one call at a time (the
// engine's pacing and the search credit guard assume it), calls sent side by
// side waiting in a queue of 256, warnings to stderr.
func (s *Server) Build() (*mcptool.Server, error) {
	ms, err := mcptool.New(mcptool.Info{Name: serverName, Version: s.Version, Instructions: instructions}, mcptool.Options{})
	if err != nil {
		return nil, err
	}
	handlers := map[string]func(mcptool.Tool) error{
		ToolLookupHost:     func(t mcptool.Tool) error { return mcptool.Add(ms, t, s.lookupHost) },
		ToolGetService:     func(t mcptool.Tool) error { return mcptool.Add(ms, t, s.getService) },
		ToolCountServices:  func(t mcptool.Tool) error { return mcptool.Add(ms, t, s.countServices) },
		ToolGetHistory:     func(t mcptool.Tool) error { return mcptool.Add(ms, t, s.getHistory) },
		ToolParseQuery:     func(t mcptool.Tool) error { return mcptool.Add(ms, t, s.parseQuery) },
		ToolSearchServices: func(t mcptool.Tool) error { return mcptool.Add(ms, t, s.searchServices) },
		ToolGetQuota: func(t mcptool.Tool) error {
			return mcptool.AddNoArgs(ms, t, func(ctx context.Context) (any, error) {
				q, err := s.Eng.GetQuota(ctx)
				return answer(q, err)
			})
		},
		ToolCacheStatus: func(t mcptool.Tool) error {
			return mcptool.AddNoArgs(ms, t, func(context.Context) (any, error) { return answer(s.cacheStatus(), nil) })
		},
		// The manual itself, as Markdown: no budget applies to it.
		ToolGetUsage: func(t mcptool.Tool) error {
			return mcptool.AddNoArgs(ms, t, func(context.Context) (any, error) { return mcptool.Text(UsageDoc()), nil })
		},
	}
	for _, def := range toolDefinitions() {
		name, okName := def["name"].(string)
		desc, okDesc := def["description"].(string)
		if !okName || !okDesc {
			return nil, fmt.Errorf("tool %v: name and description must be strings", def["name"])
		}
		schema, err := json.Marshal(def["inputSchema"])
		if err != nil {
			return nil, fmt.Errorf("tool %s: %w", name, err)
		}
		add, ok := handlers[name]
		if !ok {
			return nil, fmt.Errorf("tool %s has no handler", name)
		}
		if err := add(mcptool.Tool{Name: name, Description: desc, InputSchema: schema}); err != nil {
			return nil, fmt.Errorf("tool %s: %w", name, err)
		}
	}
	return ms, nil
}

// answer is what every tool but get_usage returns: v held to the response
// budget (budget.go), or err as a structured tool error.
func answer(v any, err error) (any, error) {
	if err != nil {
		return nil, toolError(err)
	}
	return withinCeiling(v)
}

// toolError gives err the code an agent branches on. The engine's
// invalid_argument — the CLI's code, which stays there — is mcptool's
// invalid_arguments here, naming the argument (ADR-0002); every other engine
// and client code passes through; an error nothing classified is
// internal_error, never the caller's fault.
func toolError(err error) error {
	var te *mcptool.Error
	if errors.As(err, &te) {
		return te
	}
	switch code := engine.Code(err); code {
	case "":
		return mcptool.NewError(mcptool.CodeInternal, err.Error())
	case engine.CodeInvalidArgument:
		e := mcptool.NewError(mcptool.CodeInvalidArguments, err.Error())
		if arg := engine.Argument(err); arg != "" {
			e = e.With("argument", arg)
		}
		return e
	default:
		return mcptool.NewError(code, err.Error())
	}
}

// invalidArg refuses the argument arg inside a handler: the same code as a
// refusal at decoding, so a caller handles argument errors by one code.
func invalidArg(arg, msg string) error {
	return mcptool.NewError(mcptool.CodeInvalidArguments, msg).With("argument", arg)
}
