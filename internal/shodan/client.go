// Package shodan is the read-only client of the Shodan REST API: pacing, the
// key in the query string (the only way Shodan accepts it), and the mapping of
// every upstream status onto stable error codes.
//
// The key must never appear on an output surface. Go's *url.Error quotes the
// whole request URL, and the URL carries the key, so no error built here ever
// holds a URL: messages name the endpoint (path and query without the key),
// transport errors are unwrapped to their cause, and as a second guard any
// occurrence of the key in a message is replaced before it leaves. Redirects
// are refused outright — Go would carry the query, key included, to wherever
// the Location points.
//
// Status codes mean what was measured (RFP §7 and its Phase 1 corrections):
// 401 arrives as text/plain and only from count, tokens and /api-info — host
// lookups do not check the key; a 404 carries one of two API bodies, and the
// caller decides what each means for its endpoint; a syntax error can come
// back as a 500.
package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nlink-jp/shodan-lookup/internal/termsafe"
)

// Stable error codes an agent can branch on. New codes are a compatible
// change; renaming one is breaking. Every code is documented in the MCP manual
// — a meta-test in internal/mcp pins that.
const (
	// CodeMissingKey: no API key is configured. Nothing was sent.
	CodeMissingKey = "missing_api_key"
	// CodeAuthFailed: Shodan refused the key (401).
	CodeAuthFailed = "auth_failed"
	// CodeBadRequest: Shodan rejected the query (400).
	CodeBadRequest = "bad_request"
	// CodeRateLimited: a 429.
	CodeRateLimited = "rate_limited"
	// CodeEndpoint: the exchange did not reach the API as this client knows
	// it — a 404 the caller has no reading for, a redirect, a path that has
	// moved. Never "the thing you asked about does not exist".
	CodeEndpoint = "endpoint_unavailable"
	// CodeUpstream: 5xx, an unmapped status, and anything else upstream said
	// that is not an answer.
	CodeUpstream = "upstream_error"
	// CodeNetwork: the exchange itself failed.
	CodeNetwork = "network_error"
	// CodeTimeout: the exchange did not finish in time.
	CodeTimeout = "timeout"
	// CodeDecode: a 2xx whose body is not JSON, or not the shape this client
	// was written against.
	CodeDecode = "decode_error"
)

// Error is a structured client error.
type Error struct {
	Code     string
	Message  string
	Status   int    // HTTP status, 0 when the exchange never completed
	APIError string // the "error" string of an API-shaped body, printable; "" when none
}

func (e *Error) Error() string { return e.Message }

// Code returns the stable error code, or "" when err did not come from this
// client.
func Code(err error) string {
	var ee *Error
	if errors.As(err, &ee) {
		return ee.Code
	}
	return ""
}

// MissingKey is the error for a query attempted with no key configured.
func MissingKey() *Error {
	return &Error{Code: CodeMissingKey, Message: "no Shodan API key is configured: set key under [api] in the config file, or SHODAN_LOOKUP_API_KEY (nothing was sent)"}
}

// maxBody bounds one response read. The largest measured was a 6.4 MB host
// history; a host record measured up to 991 KB.
const maxBody = 32 << 20

// Doer is the part of http.Client this package uses, so tests can stand in.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client is a read-only client of the Shodan REST API.
type Client struct {
	baseURL string
	key     string
	ua      string
	doer    Doer
	now     func() time.Time
	pace    *pacer
}

// New builds a client. baseURL is the API root without a trailing slash;
// minInterval is the least time between two requests from this process.
func New(baseURL, key string, timeout, minInterval time.Duration, userAgent string) *Client {
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		key:     key,
		ua:      userAgent,
		doer: &http.Client{
			Timeout: timeout,
			// Never follow a redirect: the key is in the query string.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now: time.Now,
	}
	c.pace = &pacer{interval: minInterval, now: c.now, sleep: sleepCtx}
	return c
}

// WithDoer replaces the HTTP transport. For tests; a replacement must refuse
// redirects itself.
func (c *Client) WithDoer(d Doer) *Client { c.doer = d; return c }

// WithClock replaces the clock and the sleep the pacer uses. For tests.
func (c *Client) WithClock(now func() time.Time, sleep func(context.Context, time.Duration) error) *Client {
	c.now = now
	c.pace.now, c.pace.sleep = now, sleep
	return c
}

// Response is one successful exchange: the upstream body as it arrived. The
// body is what gets cached; every view is derived from it.
type Response struct {
	Body      json.RawMessage
	Endpoint  string // path and query as requested, without the host and without the key
	FetchedAt time.Time
}

// Host fetches everything Shodan holds for one IP: GET /shodan/host/{ip}.
// The caller gates ip (internal/ipaddr) and sends its canonical form.
func (c *Client) Host(ctx context.Context, ip string) (*Response, error) {
	return c.get(ctx, "/shodan/host/"+url.PathEscape(ip), nil)
}

// Count fetches the number of services matching a query, and facet
// breakdowns: GET /shodan/host/count. Measured credit-free. facets is the
// comma-separated "name:N" list, or "".
func (c *Client) Count(ctx context.Context, query, facets string) (*Response, error) {
	q := url.Values{"query": {query}}
	if facets != "" {
		q.Set("facets", facets)
	}
	return c.get(ctx, "/shodan/host/count", q)
}

// Filters fetches the names Shodan accepts as search filters:
// GET /shodan/host/search/filters (credit-free).
func (c *Client) Filters(ctx context.Context) (*Response, error) {
	return c.get(ctx, "/shodan/host/search/filters", nil)
}

// Facets fetches the names Shodan accepts as facets:
// GET /shodan/host/search/facets (credit-free).
func (c *Client) Facets(ctx context.Context) (*Response, error) {
	return c.get(ctx, "/shodan/host/search/facets", nil)
}

// APIInfo fetches the plan and remaining credits of the key: GET /api-info.
func (c *Client) APIInfo(ctx context.Context) (*Response, error) {
	return c.get(ctx, "/api-info", nil)
}

func (c *Client) get(ctx context.Context, path string, query url.Values) (*Response, error) {
	endpoint := path
	if len(query) > 0 {
		endpoint += "?" + query.Encode() // Encode sorts keys: a stable cache key
	}
	if c.key == "" {
		return nil, MissingKey()
	}
	if err := c.pace.wait(ctx); err != nil {
		return nil, c.transportError(err, endpoint)
	}

	full := url.Values{}
	for k, v := range query {
		full[k] = v
	}
	full.Set("key", c.key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path+"?"+full.Encode(), nil)
	if err != nil {
		return nil, &Error{Code: CodeNetwork, Message: c.scrub("build request for " + endpoint + ": " + causeOf(err).Error())}
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "application/json")

	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, c.transportError(err, endpoint)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, c.transportError(err, endpoint)
	}
	if len(body) > maxBody {
		return nil, &Error{Code: CodeUpstream, Status: resp.StatusCode,
			Message: fmt.Sprintf("upstream sent more than %d MiB for %s; refusing to read it", maxBody>>20, endpoint)}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := statusError(resp.StatusCode, body, endpoint)
		e.Message = c.scrub(e.Message)
		e.APIError = c.scrub(e.APIError)
		return nil, e
	}
	if !json.Valid(body) {
		return nil, &Error{Code: CodeDecode, Status: resp.StatusCode,
			Message: "upstream answered " + strconv.Itoa(resp.StatusCode) + " for " + endpoint + " with a body that is not JSON"}
	}
	return &Response{Body: body, Endpoint: endpoint, FetchedAt: c.now()}, nil
}

// apiError is the body Shodan's own handlers send: {"error": "..."}. Anything
// that does not decode into it did not come from the API.
type apiError struct {
	Error string `json:"error"`
}

func statusError(status int, body []byte, endpoint string) *Error {
	var ae apiError
	fromAPI := json.Unmarshal(body, &ae) == nil && ae.Error != ""
	said := ""
	e := &Error{Status: status}
	if fromAPI {
		e.APIError = printable(ae.Error, 300)
		said = ": " + e.APIError
	}

	switch {
	case status >= 300 && status <= 399:
		e.Code = CodeEndpoint
		e.Message = fmt.Sprintf("upstream redirected %s (%d); redirects are refused because the API key travels in the URL — check [api] base_url", endpoint, status)
	case status == http.StatusUnauthorized:
		// Measured: a text/plain page, from count, tokens and /api-info.
		e.Code = CodeAuthFailed
		e.Message = "Shodan refused the API key (401) for " + endpoint + " — check [api] key. Host lookups do not check the key, so a wrong one shows here first"
	case status == http.StatusBadRequest:
		e.Code = CodeBadRequest
		e.Message = "Shodan rejected the query (" + endpoint + ")" + said
	case status == http.StatusTooManyRequests:
		e.Code = CodeRateLimited
		e.Message = "Shodan's rate limit was reached (429). It allows one request per second per key, shared by every process using the key"
	case status == http.StatusNotFound && fromAPI:
		// What a 404 means depends on the endpoint ("Invalid IP", "No
		// information available for that IP."); the caller reads APIError.
		e.Code = CodeEndpoint
		e.Message = "upstream answered 404 for " + endpoint + said
	case status == http.StatusNotFound:
		e.Code = CodeEndpoint
		e.Message = "upstream answered 404 for " + endpoint + " without the API's own error body — check [api] base_url"
	default:
		e.Code = CodeUpstream
		e.Message = fmt.Sprintf("upstream answered %d for %s%s", status, endpoint, said)
	}
	return e
}

// transportError reports an exchange that never completed, without the URL.
func (c *Client) transportError(err error, endpoint string) *Error {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return &Error{Code: CodeTimeout, Message: "timed out asking Shodan for " + endpoint}
	}
	if errors.Is(err, context.Canceled) {
		return &Error{Code: CodeTimeout, Message: "cancelled while asking Shodan for " + endpoint}
	}
	return &Error{Code: CodeNetwork, Message: c.scrub("could not reach Shodan for " + endpoint + ": " + printable(causeOf(err).Error(), 200))}
}

// causeOf unwraps every *url.Error, whose message quotes the full URL — and
// with it the key.
func causeOf(err error) error {
	for {
		var ue *url.Error
		if !errors.As(err, &ue) {
			return err
		}
		err = ue.Err
	}
}

// scrub is the second guard: whatever a message turned out to contain, the
// key — raw or query-escaped — does not leave in it.
func (c *Client) scrub(s string) string {
	if c.key == "" || s == "" {
		return s
	}
	s = strings.ReplaceAll(s, c.key, "[redacted]")
	if esc := url.QueryEscape(c.key); esc != c.key {
		s = strings.ReplaceAll(s, esc, "[redacted]")
	}
	return s
}

// printable makes third-party text safe to put in an error message: control
// characters become '?', and it is clipped to max runes.
func printable(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			b.WriteString("…")
			break
		}
		if termsafe.Obeyed(r) {
			r = '?'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// pacer spaces this process's requests at least interval apart. The limit is
// per key while the pacing is per process: a shell loop and the MCP servers of
// several agent runtimes spend from one key without seeing each other. That is
// why the default interval is twice the documented one, and why a 429 is
// reported rather than retried.
type pacer struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time // the earliest time the next request may start
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
}

func (p *pacer) wait(ctx context.Context) error {
	p.mu.Lock()
	now := p.now()
	start := p.next
	if start.Before(now) {
		start = now
	}
	p.next = start.Add(p.interval)
	p.mu.Unlock()
	if d := start.Sub(now); d > 0 {
		return p.sleep(ctx, d)
	}
	return ctx.Err()
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
