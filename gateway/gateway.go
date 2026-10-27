package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// Client routes the gateway-level public endpoints (SDK-API-001,
// SDK-API-002): JWKS and Health execute through the injected
// *client.Client with the routes' public auth class — no signer is
// required and no Authorization header is ever sent.
type Client struct {
	cli *client.Client
}

// New binds the gateway public routes to a configured client.
// Parameters: cli is the configured client used by JWKS and Health
// (must be non-nil).
// Returns: the routes Client, or an error on a nil client. Never
// panics.
func New(cli *client.Client) (*Client, error) {
	if cli == nil {
		return nil, errors.New("gateway: nil client")
	}
	return &Client{cli: cli}, nil
}

// JWKS fetches the gateway's key set at GET /.well-known/jwks
// (SDK-API-001) with the route's public auth class — no Authorization
// header is sent — and returns the served RFC 7517 key set.
// Parameters: ctx is the call context.
// Returns: the decoded JWKSResponse, or an error — a gateway failure
// surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) JWKS(ctx context.Context) (*wire.JWKSResponse, error) {
	resp, err := c.cli.Do(ctx, client.Request{
		Method: http.MethodGet,
		Path:   "/.well-known/jwks",
		Auth:   wire.AuthPublic,
	})
	if err != nil {
		return nil, err
	}
	var out wire.JWKSResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("gateway: jwks: %w", err)
	}
	return &out, nil
}

// Health probes the gateway at GET /health (SDK-API-001) with the
// route's public auth class — no Authorization header is sent — and
// decodes the status body.
// Parameters: ctx is the call context.
// Returns: the decoded GatewayHealthResponse, or an error — a gateway
// failure surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) Health(ctx context.Context) (*wire.GatewayHealthResponse, error) {
	resp, err := c.cli.Do(ctx, client.Request{
		Method: http.MethodGet,
		Path:   "/health",
		Auth:   wire.AuthPublic,
	})
	if err != nil {
		return nil, err
	}
	var out wire.GatewayHealthResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("gateway: health: %w", err)
	}
	return &out, nil
}
