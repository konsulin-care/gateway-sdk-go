package client

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// Client is the one Client core (SDK-CLIENT-001); all parts injected via
// functional options, no silent production defaults (SDK-CLIENT-C01).
type Client struct {
	baseURL    *url.URL
	partyID    string
	signer     crypto.Signer
	httpClient *http.Client
	replay     ReplayCache
	logger     *slog.Logger
	retry      RetryPolicy
}

// New builds a Client from opts (SDK-CLIENT-001): WithBaseURL is required,
// no silent defaults (SDK-CLIENT-C01); invalid option values (nil signer,
// HTTP client, logger, malformed URL) fail New rather than being ignored.
// Returns: the Client, or an error and nil.
func New(opts ...Option) (*Client, error) {
	cfg := config{retry: RetryPolicy{MaxAttempts: 1}}
	for _, opt := range opts {
		if opt == nil {
			return nil, errors.New("client: nil option")
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	if cfg.baseURL == "" {
		return nil, errors.New("client: WithBaseURL is required (SDK-CLIENT-C01: no silent default)")
	}
	base, err := transportURL(cfg.baseURL, cfg.insecure)
	if err != nil {
		return nil, err
	}
	c := &Client{baseURL: base, partyID: cfg.partyID, signer: cfg.signer,
		httpClient: cfg.httpClient, replay: cfg.replay, logger: cfg.logger, retry: cfg.retry}
	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	return c, nil
}

// Do executes req against the base URL (SDK-CLIENT-001), honouring ctx: a
// cancelled context aborts with a context error. An idempotent request
// (Request.Idempotent) carries one Idempotency-Key — the caller's
// IdempotencyKey when set, otherwise one generated for the call — held
// stable across every attempt of the same logical create; a terminal 402
// or a changed body ends the key's life (SDK-CLIENT-002, ADR-011).
// AuthParty signs a fresh ks-party+jwt per attempt (iss = party id, aud =
// gateway, exact typ) and fails with ErrNoSigner before any network I/O.
// Responses classify per the Error catalog (SDK-RETRY-003): a retryable
// status/code (wire.Retryable) costs one more attempt within
// RetryPolicy.MaxAttempts, reusing the same key; anything terminal returns
// immediately. A 2xx returns the response with its buffered body; any
// other status surfaces as the one error type *wire.Error parsed from the
// error envelope (SDK-CLIENT-003) — a non-envelope body carries the HTTP
// status with an empty code, never a panic. Call options (WithResponseMeta)
// observe the final completed response, on success and failure alike, with
// the sent Idempotency-Key in the captured header. Logged via the injected
// logger — method, path, status, request_id only, never bodies or tokens
// (PRD §8). Returns: the response with its buffered body, or an error.
func (c *Client) Do(ctx context.Context, req Request, opts ...CallOption) (*Response, error) {
	switch {
	case ctx == nil:
		return nil, errors.New("client: nil context")
	case req.Method == "":
		return nil, errors.New("client: request method must not be empty")
	case !strings.HasPrefix(req.Path, "/"):
		return nil, fmt.Errorf("client: request path %q must start with /", req.Path)
	}
	cc, err := applyCallOptions(opts)
	if err != nil {
		return nil, err
	}
	if req.Auth == wire.AuthParty && c.signer == nil {
		return nil, ErrNoSigner
	}
	key := req.IdempotencyKey
	if req.Idempotent && key == "" {
		if key, err = newIdempotencyKey(); err != nil {
			return nil, err
		}
	}
	attempts := c.retry.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	var out *Response
	for attempt := 1; ; attempt++ {
		if out, err = c.attempt(ctx, req, key); err != nil {
			return nil, err
		}
		if attempt >= attempts || !retryableResponse(out) {
			break
		}
	}
	meta := out.Header.Clone()
	if key != "" {
		meta.Set("Idempotency-Key", key)
	}
	cc.capture(ResponseMeta{Status: out.StatusCode, RequestID: meta.Get("X-Request-Id"), Header: meta})
	return outcome(out)
}

// retryableResponse classifies one completed gateway response for the
// attempt loop (SDK-RETRY-003): a 2xx is never retryable; anything else
// defers to the catalog disposition via wire.Retryable on the parsed error
// code, with the status fallback for unrecognised or missing codes.
// Parameters: resp — the completed response with its buffered body.
// Returns: whether one more attempt within the policy may succeed.
func retryableResponse(resp *Response) bool {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return false
	}
	return wire.Retryable(resp.StatusCode, wire.DecodeError(resp.StatusCode, resp.Body).Code)
}

// attempt executes one network attempt of req under the given
// Idempotency-Key: it signs a fresh ks-party+jwt when the route is
// AuthParty (ADR-008 — the key identifies the operation, the jti the
// attempt), builds the request against the base URL, sends it through the
// injected *http.Client, and buffers the response body. Logged via the
// injected logger — method, path, status, request_id only (PRD §8).
// Parameters: ctx — the call context; req — the outbound request; key —
// the Idempotency-Key to send, empty sends none. Returns: the response
// with its buffered body, or an error (signing, build, transport, read).
func (c *Client) attempt(ctx context.Context, req Request, key string) (*Response, error) {
	token := ""
	if req.Auth == wire.AuthParty {
		var err error
		if token, err = c.signPartyRequest(); err != nil {
			return nil, err
		}
	}
	target := *c.baseURL
	target.Path = strings.TrimSuffix(c.baseURL.Path, "/") + req.Path
	target.RawQuery = ""
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, target.String(), bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("client: build request: %w", err)
	}
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		httpReq.Header.Set("Idempotency-Key", key)
	}
	if len(req.Body) > 0 {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		c.logger.ErrorContext(ctx, "gateway request failed", "method", req.Method, "path", req.Path)
		return nil, fmt.Errorf("client: %s %s: %w", req.Method, req.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("client: read response body: %w", err)
	}
	c.logger.InfoContext(ctx, "gateway response", "method", req.Method, "path", req.Path,
		"status", resp.StatusCode, "request_id", resp.Header.Get("X-Request-Id"))
	return &Response{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: body}, nil
}
