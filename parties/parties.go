package parties

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// Client routes the party lifecycle endpoints (SDK-API-001, SDK-API-002):
// Enroll and EnrollES256 send their own HTTP requests (the enrollment PoP
// proof cannot be produced by client signing), while Rotate, JWKS, and
// Health execute through the injected *client.Client. The gateway base URL
// is kept here because the client exposes no base-URL accessor.
type Client struct {
	cli  *client.Client
	base string
	hc   *http.Client
}

// New binds the party routes to a configured client and gateway base URL.
// Parameters: cli is the configured client used for Rotate/JWKS/Health
// (must be non-nil); gatewayURL is the absolute gateway base URL the
// enrollment requests target — it must already have passed the client's
// transport guard at client construction (SDK-CLIENT-C01), so no second
// guard is applied here.
// Returns: the routes Client, or an error. Never panics.
func New(cli *client.Client, gatewayURL string) (*Client, error) {
	if cli == nil {
		return nil, errors.New("parties: nil client")
	}
	u, err := url.Parse(gatewayURL)
	if err != nil {
		return nil, fmt.Errorf("parties: gateway URL %q: %w", gatewayURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("parties: gateway URL %q: absolute URL required", gatewayURL)
	}
	return &Client{cli: cli, base: strings.TrimSuffix(u.String(), "/"), hc: http.DefaultClient}, nil
}

// Rotate installs a new key at POST /v1/parties/{id}/keys
// (SDK-API-002): the request is signed by the client's party signer
// (AuthParty), carries an Idempotency-Key (an idempotent create,
// SDK-CLIENT-002), and the 200 body decodes into the returned kid.
// Parameters: ctx is the call context; partyID is the rotating party's
// id; req is the new key material.
// Returns: the decoded RotateKeyResponse, or an error — a gateway
// failure surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) Rotate(ctx context.Context, partyID string, req wire.RotateKeyRequest) (*wire.RotateKeyResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("parties: rotate: request JSON: %w", err)
	}
	resp, err := c.cli.Do(ctx, client.Request{
		Method:     http.MethodPost,
		Path:       "/v1/parties/" + url.PathEscape(partyID) + "/keys",
		Body:       body,
		Auth:       wire.AuthParty,
		Idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	var out wire.RotateKeyResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("parties: rotate: %w", err)
	}
	return &out, nil
}

// JWKS fetches the party's key set at GET /v1/parties/{id}/jwks
// (SDK-ENV-002: any counterparty party may be queried) with the route's
// public auth class — no Authorization header is sent.
// Parameters: ctx is the call context; partyID is the party whose keys
// are fetched.
// Returns: the decoded JWKSResponse, or an error (*wire.Error on gateway
// failure). Never panics.
func (c *Client) JWKS(ctx context.Context, partyID string) (*wire.JWKSResponse, error) {
	resp, err := c.cli.Do(ctx, client.Request{
		Method: http.MethodGet,
		Path:   "/v1/parties/" + url.PathEscape(partyID) + "/jwks",
		Auth:   wire.AuthPublic,
	})
	if err != nil {
		return nil, err
	}
	var out wire.JWKSResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("parties: jwks: %w", err)
	}
	return &out, nil
}

// Health probes the party's health at GET /v1/parties/{id}/health with
// the route's party auth class — a Bearer party token.
// Parameters: ctx is the call context; partyID is the party probed.
// Returns: the decoded PartyHealthResponse, or an error (*wire.Error on
// gateway failure). Never panics.
func (c *Client) Health(ctx context.Context, partyID string) (*wire.PartyHealthResponse, error) {
	resp, err := c.cli.Do(ctx, client.Request{
		Method: http.MethodGet,
		Path:   "/v1/parties/" + url.PathEscape(partyID) + "/health",
		Auth:   wire.AuthParty,
	})
	if err != nil {
		return nil, err
	}
	var out wire.PartyHealthResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("parties: health: %w", err)
	}
	return &out, nil
}
