package identities

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// Client routes the identity endpoints (SDK-API-001, SDK-API-002):
// Register, Resolve, and Link all execute through the injected
// *client.Client with the route's party auth class — every call is
// signed by the client's party signer (AuthParty).
type Client struct {
	cli *client.Client
}

// New binds the identity routes to a configured client.
// Parameters: cli is the configured client used by Register, Resolve,
// and Link (must be non-nil).
// Returns: the routes Client, or an error on a nil client. Never panics.
func New(cli *client.Client) (*Client, error) {
	if cli == nil {
		return nil, errors.New("identities: nil client")
	}
	return &Client{cli: cli}, nil
}

// Register registers a hashed identity for one party-local resource at
// POST /v1/identities/register (SDK-API-001): the request is signed by
// the client's party signer (AuthParty), carries an Idempotency-Key (an
// idempotent create, SDK-CLIENT-002), and the 200 body decodes into the
// returned global key.
// Parameters: ctx is the call context; req is the hashed identity to
// register.
// Returns: the decoded RegisterIdentityResponse, or an error — a gateway
// failure surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) Register(ctx context.Context, req wire.RegisterIdentityRequest) (*wire.RegisterIdentityResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("identities: register: request JSON: %w", err)
	}
	resp, err := c.cli.Do(ctx, client.Request{
		Method:     http.MethodPost,
		Path:       "/v1/identities/register",
		Body:       body,
		Auth:       wire.AuthParty,
		Idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	var out wire.RegisterIdentityResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("identities: register: %w", err)
	}
	return &out, nil
}

// Resolve resolves hashed identity fields to candidate links at POST
// /v1/identities/resolve (SDK-API-001): the request is signed by the
// client's party signer (AuthParty) and — as a read, not a create —
// sends no Idempotency-Key.
// Parameters: ctx is the call context; req holds the hashed fields to
// resolve.
// Returns: the decoded ResolveIdentityResponse (an empty candidate list
// is a valid result, never an error), or an error — a gateway failure
// surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) Resolve(ctx context.Context, req wire.ResolveIdentityRequest) (*wire.ResolveIdentityResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("identities: resolve: request JSON: %w", err)
	}
	resp, err := c.cli.Do(ctx, client.Request{
		Method: http.MethodPost,
		Path:   "/v1/identities/resolve",
		Body:   body,
		Auth:   wire.AuthParty,
	})
	if err != nil {
		return nil, err
	}
	var out wire.ResolveIdentityResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("identities: resolve: %w", err)
	}
	return &out, nil
}

// Link declares equivalence between a global key and a party-local
// resource at POST /v1/identities/link (SDK-API-001): the request is
// signed by the client's party signer (AuthParty), carries an
// Idempotency-Key (an idempotent create, SDK-CLIENT-002), and the 200
// body decodes into the link result.
// Parameters: ctx is the call context; req names the confirmed global
// key and the local resource it links.
// Returns: the decoded LinkIdentityResponse, or an error — a gateway
// failure surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) Link(ctx context.Context, req wire.LinkIdentityRequest) (*wire.LinkIdentityResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("identities: link: request JSON: %w", err)
	}
	resp, err := c.cli.Do(ctx, client.Request{
		Method:     http.MethodPost,
		Path:       "/v1/identities/link",
		Body:       body,
		Auth:       wire.AuthParty,
		Idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	var out wire.LinkIdentityResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("identities: link: %w", err)
	}
	return &out, nil
}
