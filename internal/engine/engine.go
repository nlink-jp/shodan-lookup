// Package engine is the shared core of the CLI and the MCP server: the gate,
// the cache, the upstream client and the projection, in that order. It
// returns complete views of this tool's own schema; what a tool result may
// cost in a client's context is decided at the MCP boundary, never here, so
// the CLI's --json stays complete.
//
// The unit the cache stores is the upstream body. Every view — the host
// projection, one section of one service, --raw — is derived from that one
// entry, so paging a section never fetches again and no view has a slot of
// its own. Never cached: the quota (account state), a "not indexed" answer,
// and anything degraded.
//
// Negative answers are never manufactured (RFP §3 and its Phase 1
// corrections). Shodan's 404 "No information available for that IP." also
// comes from upstream failures, so it is cross-checked with a credit-free
// count before it is called not_indexed. Unknown filter and facet names are
// silent no-ops upstream, so they are checked against upstream's own lists
// before anything is sent; vuln and tag are refused because on this plan
// their restriction reads as a low count, not as an error.
package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/config"
	"github.com/nlink-jp/shodan-lookup/internal/ipaddr"
	"github.com/nlink-jp/shodan-lookup/internal/shodan"
)

// Stable error codes the engine adds to the client's. Every code is
// documented in the MCP manual — a meta-test pins that.
const (
	// CodeInvalidArgument: the input was refused before anything was sent.
	CodeInvalidArgument = "invalid_argument"
	// CodeNotIndexed: Shodan holds nothing for the IP — it has not observed
	// it. Confirmed by a credit-free count, never taken from a 404 alone.
	CodeNotIndexed = "not_indexed"
	// CodeNotObserved: the host is indexed, but Shodan has no banner for the
	// port asked about. Not "closed".
	CodeNotObserved = "not_observed"
	// CodePlanRestricted: the query uses a filter or facet Shodan withholds
	// from this plan. Refused before sending, because the restriction does
	// not come back as an error: it reads as a low count.
	CodePlanRestricted = "plan_restricted"
)

// Error is a structured engine error.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// Code returns the stable code of an engine, gate or client error, or "" when
// err is none of those.
func Code(err error) string {
	var ee *Error
	if errors.As(err, &ee) {
		return ee.Code
	}
	var ie *ipaddr.Error
	if errors.As(err, &ie) {
		return CodeInvalidArgument
	}
	return shodan.Code(err)
}

func invalid(msg string) error { return &Error{Code: CodeInvalidArgument, Message: msg} }

// Upstream is the part of the Shodan client the engine calls, so tests can
// stand in for it.
type Upstream interface {
	Host(ctx context.Context, ip string) (*shodan.Response, error)
	Count(ctx context.Context, query, facets string) (*shodan.Response, error)
	Filters(ctx context.Context) (*shodan.Response, error)
	Facets(ctx context.Context) (*shodan.Response, error)
	APIInfo(ctx context.Context) (*shodan.Response, error)
}

// Engine is the shared core.
type Engine struct {
	cfg   *config.Config
	up    Upstream
	cache *cache.Store
	now   func() time.Time
}

// New builds an engine over an upstream client and a cache.
func New(cfg *config.Config, up Upstream, store *cache.Store) *Engine {
	return &Engine{cfg: cfg, up: up, cache: store, now: time.Now}
}

// WithClock replaces the clock. For tests.
func (e *Engine) WithClock(now func() time.Time) *Engine { e.now = now; return e }

// Provenance says where an answer came from and how old it is. It never holds
// a request URL: the key travels in the URL.
type Provenance struct {
	Source    string `json:"source"`
	Endpoint  string `json:"endpoint"`
	FetchedAt string `json:"fetched_at"`
	Cached    bool   `json:"cached"`
	DocID     string `json:"doc_id,omitempty"`
}

// entry is what the cache stores: the upstream body, with the time and the
// endpoint it came from.
type entry struct {
	FetchedAt time.Time       `json:"fetched_at"`
	Endpoint  string          `json:"endpoint"`
	Body      json.RawMessage `json:"body"`
}

func (e *Engine) checkKey() error {
	if !e.cfg.HasKey() {
		// Checked before the cache, so that a cached answer is not served on
		// a machine with no key either.
		return shodan.MissingKey()
	}
	return nil
}

// fetch reads one upstream body through the cache. ttl 0 means this kind is
// not cached at all: no read, no write.
func (e *Engine) fetch(ctx context.Context, key string, ttl time.Duration, refresh bool,
	get func(context.Context) (*shodan.Response, error)) (*entry, bool, error) {
	if !refresh && ttl > 0 {
		if raw, ok := e.cache.Get(key, e.now(), ttl); ok {
			var en entry
			if json.Unmarshal(raw, &en) == nil && len(en.Body) > 0 {
				return &en, true, nil
			}
		}
	}
	resp, err := get(ctx)
	if err != nil {
		return nil, false, err
	}
	// The body is compacted once, here, and stored exactly so: a fresh
	// answer and a cached one must be the same bytes, or the doc_id of one
	// record would change between its first page and its second.
	var compact bytes.Buffer
	if err := json.Compact(&compact, resp.Body); err != nil {
		return nil, false, &shodan.Error{Code: shodan.CodeDecode, Message: "upstream body for " + resp.Endpoint + " is not JSON: " + err.Error()}
	}
	en := &entry{FetchedAt: resp.FetchedAt.UTC(), Endpoint: resp.Endpoint, Body: compact.Bytes()}
	if ttl > 0 {
		// Written without HTML escaping: json.Marshal would turn < > & inside
		// the body into \u003c and friends, and the cached bytes would no
		// longer be the fetched ones.
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(en); err == nil {
			_ = e.cache.Put(key, bytes.TrimSpace(b.Bytes()), e.now()) // a cache that cannot be written is not an error for the answer
		}
	}
	return en, false, nil
}

func provenance(en *entry, cached bool) Provenance {
	return Provenance{Source: "shodan", Endpoint: en.Endpoint, FetchedAt: en.FetchedAt.Format(time.RFC3339), Cached: cached}
}

func docID(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:8])
}
