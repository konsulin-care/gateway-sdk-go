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

// Do executes one attempt of req against the base URL (SDK-CLIENT-001),
// honouring ctx: a cancelled context aborts with a context error. AuthParty
// signs a fresh ks-party+jwt per attempt (iss = party id, aud = gateway,
// exact typ) and fails with ErrNoSigner before any network I/O. Logged via
// the injected logger — method, path, status, request_id only, never bodies
// or tokens (PRD §8). Returns: the response with its buffered body, or an
// error.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	switch {
	case ctx == nil:
		return nil, errors.New("client: nil context")
	case req.Method == "":
		return nil, errors.New("client: request method must not be empty")
	case !strings.HasPrefix(req.Path, "/"):
		return nil, fmt.Errorf("client: request path %q must start with /", req.Path)
	}
	token := ""
	if req.Auth == wire.AuthParty {
		if c.signer == nil {
			return nil, ErrNoSigner
		}
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
	if req.IdempotencyKey != "" {
		httpReq.Header.Set("Idempotency-Key", req.IdempotencyKey)
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
