package payments

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

// Client routes the payment endpoints (SDK-API-001, SDK-API-002):
// Create, Get, and AccessToken all execute through the injected
// *client.Client with the route's party auth class — every call is
// signed by the client's party signer (AuthParty).
type Client struct {
	cli *client.Client
}

// New binds the payment routes to a configured client.
// Parameters: cli is the configured client used by Create, Get, and
// AccessToken (must be non-nil).
// Returns: the routes Client, or an error on a nil client. Never
// panics.
func New(cli *client.Client) (*Client, error) {
	if cli == nil {
		return nil, errors.New("payments: nil client")
	}
	return &Client{cli: cli}, nil
}

// Create initiates a payment at POST /v1/payments (SDK-API-001): the
// request is signed by the client's party signer (AuthParty), carries
// an Idempotency-Key (an idempotent create, SDK-CLIENT-002), and the
// 200 body decodes into the created payment — the priced path carries
// a checkout link, the free path settles immediately with explicit
// nulls and status PAID.
// Parameters: ctx is the call context; req is the payment to initiate —
// exactly one of listing mode (listing_id) or seller-amount mode
// (domain + opaque + amount).
// Returns: the decoded CreatePaymentResponse, or an error — a gateway
// failure surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) Create(ctx context.Context, req wire.CreatePaymentRequest) (*wire.CreatePaymentResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("payments: create: request JSON: %w", err)
	}
	resp, err := c.cli.Do(ctx, client.Request{
		Method:     http.MethodPost,
		Path:       "/v1/payments",
		Body:       body,
		Auth:       wire.AuthParty,
		Idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	var out wire.CreatePaymentResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("payments: create: %w", err)
	}
	return &out, nil
}

// Get fetches one buyer-owned payment at GET /v1/payments/{id}
// (SDK-API-001): the request is signed by the client's party signer
// (AuthParty) and — as a read, not a create — sends no
// Idempotency-Key.
// Parameters: ctx is the call context; paymentID is the payment to
// reconcile.
// Returns: the decoded GetPaymentResponse, or an error — a gateway
// failure surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) Get(ctx context.Context, paymentID string) (*wire.GetPaymentResponse, error) {
	resp, err := c.cli.Do(ctx, client.Request{
		Method: http.MethodGet,
		Path:   "/v1/payments/" + url.PathEscape(paymentID),
		Auth:   wire.AuthParty,
	})
	if err != nil {
		return nil, err
	}
	var out wire.GetPaymentResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("payments: get: %w", err)
	}
	return &out, nil
}

// AccessToken mints the direct-channel access ticket at POST
// /v1/payments/{id}/access-token (SDK-API-001): the request is signed
// by the client's party signer (AuthParty), carries an
// Idempotency-Key (an idempotent create, SDK-CLIENT-002), sends no
// request body, and the 200 body decodes into the minted ks-access+jwt
// ticket with its short expiry.
// Parameters: ctx is the call context; paymentID is the paid payment
// whose access is granted.
// Returns: the decoded AccessTokenResponse, or an error — a gateway
// failure surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) AccessToken(ctx context.Context, paymentID string) (*wire.AccessTokenResponse, error) {
	resp, err := c.cli.Do(ctx, client.Request{
		Method:     http.MethodPost,
		Path:       "/v1/payments/" + url.PathEscape(paymentID) + "/access-token",
		Auth:       wire.AuthParty,
		Idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	var out wire.AccessTokenResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("payments: access-token: %w", err)
	}
	return &out, nil
}
