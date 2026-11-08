package listings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// Client routes the marketplace listing endpoints (SDK-API-001,
// SDK-API-002): Create and List both execute through the injected
// *client.Client with the route's auth class — Create signed by the
// client's party signer (AuthParty), List sent unauthenticated
// (AuthPublic).
type Client struct {
	cli *client.Client
}

// New binds the listing routes to a configured client.
// Parameters: cli is the configured client used by Create and List
// (must be non-nil).
// Returns: the routes Client, or an error on a nil client. Never
// panics.
func New(cli *client.Client) (*Client, error) {
	if cli == nil {
		return nil, errors.New("listings: nil client")
	}
	return &Client{cli: cli}, nil
}

// Create enlists a service or commodity in the marketplace at POST
// /v1/listings (SDK-API-001): the request is signed by the client's
// party signer (AuthParty), carries an Idempotency-Key (an idempotent
// create, SDK-CLIENT-002), and the 200 body decodes into the created
// listing id and state.
// Parameters: ctx is the call context; req is the listing to enlist —
// name, endpoint URL, price, and the optional invocation, price scope,
// and metering discriminators.
// Returns: the decoded CreateListingResponse, or an error — a gateway
// failure surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) Create(ctx context.Context, req wire.CreateListingRequest) (*wire.CreateListingResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("listings: create: request JSON: %w", err)
	}
	resp, err := c.cli.Do(ctx, client.Request{
		Method:     http.MethodPost,
		Path:       "/v1/listings",
		Body:       body,
		Auth:       wire.AuthParty,
		Idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	var out wire.CreateListingResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("listings: create: %w", err)
	}
	return &out, nil
}

// List fetches the active marketplace listings at GET /v1/listings
// (SDK-API-001) with the route's public auth class — no Authorization
// header is sent and, as a read, no Idempotency-Key. Every decoded row
// carries metering ("gateway" or "provider"); endpoint_url is present
// for commodity rows and omitted for invocation=webhook rows — the
// public read never exposes a provider endpoint.
// Parameters: ctx is the call context; opts are the optional GWP-005
// filters (WithName, WithProviderPartyID, WithInvocation) encoded as
// query parameters — with no options no query string is sent.
// Returns: the decoded GetListingsResponse (active listings only), or
// an error — a gateway failure surfaces as *wire.Error
// (SDK-CLIENT-003). Never panics.
func (c *Client) List(ctx context.Context, opts ...ListOption) (*wire.GetListingsResponse, error) {
	req := client.Request{
		Method: http.MethodGet,
		Path:   "/v1/listings",
		Auth:   wire.AuthPublic,
	}
	if len(opts) > 0 {
		q := make(url.Values, len(opts))
		for _, opt := range opts {
			if opt != nil {
				opt(q)
			}
		}
		req.Query = q
	}
	resp, err := c.cli.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	var out wire.GetListingsResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("listings: list: %w", err)
	}
	return &out, nil
}
