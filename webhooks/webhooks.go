package webhooks

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

// Client routes the webhook endpoints (SDK-API-001, SDK-API-002):
// Enqueue, Sync, Status, and Result execute through the injected
// *client.Client — Enqueue, Sync and Status are signed by the client's
// party signer (AuthParty), Result presents the caller's party token.
// ResultWithTicket sends its own single-attempt request with the
// engine's Bearer result ticket, so the gateway base URL is kept here
// (the client exposes no base-URL accessor).
type Client struct {
	cli  *client.Client
	base string
	hc   *http.Client
}

// New binds the webhook routes to a configured client and gateway base
// URL.
// Parameters: cli is the configured client used by every Do-routed
// route (must be non-nil); gatewayURL is the absolute gateway base URL
// the result-ticket request targets — it must already have passed the
// client's transport guard at client construction (SDK-CLIENT-C01), so
// no second guard is applied here.
// Returns: the routes Client, or an error on a nil client or a
// non-absolute URL. Never panics.
func New(cli *client.Client, gatewayURL string) (*Client, error) {
	if cli == nil {
		return nil, errors.New("webhooks: nil client")
	}
	u, err := url.Parse(gatewayURL)
	if err != nil {
		return nil, fmt.Errorf("webhooks: gateway URL %q: %w", gatewayURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("webhooks: gateway URL %q: absolute URL required", gatewayURL)
	}
	return &Client{cli: cli, base: strings.TrimSuffix(u.String(), "/"), hc: http.DefaultClient}, nil
}

// Enqueue queues one async marketplace invocation at POST /v1/webhooks
// (SDK-API-001): the request is signed by the client's party signer
// (AuthParty), carries an Idempotency-Key (an idempotent create,
// SDK-CLIENT-002), and the 202 body decodes into the outbox row id.
// Parameters: ctx is the call context; req is the invocation to queue —
// provider party, listing service name, optional user-scoped hash, and
// the opaque payload relayed verbatim.
// Returns: the decoded EnqueueWebhookResponse, or an error — a gateway
// failure surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) Enqueue(ctx context.Context, req wire.EnqueueWebhookRequest) (*wire.EnqueueWebhookResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("webhooks: enqueue: request JSON: %w", err)
	}
	resp, err := c.cli.Do(ctx, client.Request{
		Method:     http.MethodPost,
		Path:       "/v1/webhooks",
		Body:       body,
		Auth:       wire.AuthParty,
		Idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	var out wire.EnqueueWebhookResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("webhooks: enqueue: %w", err)
	}
	return &out, nil
}

// SyncResult is one Sync outcome: the gateway's relay envelope body plus
// the provider's X-Quota-Remaining response header relayed verbatim on
// 2xx (provider-metered listings). QuotaRemaining is nil when the
// gateway sent no such header — the provider sent none.
type SyncResult struct {
	*wire.SyncWebhookResponse
	// QuotaRemaining is the verbatim X-Quota-Remaining header value,
	// nil when the header is absent.
	QuotaRemaining *string
}

// Sync forwards one invocation inline at POST /v1/webhooks/sync
// (SDK-API-001): party-signed (AuthParty), carries an Idempotency-Key
// (SDK-CLIENT-002), and the 200 body decodes into the relayed upstream
// response. The provider's X-Quota-Remaining header is exposed
// verbatim on the returned SyncResult (SDK-WIRE-001).
// Parameters: ctx is the call context; req is the inline invocation —
// provider party, listing service name, optional user-scoped hash, and
// the opaque payload relayed verbatim.
// Returns: the decoded SyncResult, or an error — a terminal 402
// GW-HOOK-006 returns after one attempt as *wire.Error (SDK-RETRY-003).
// Never panics.
func (c *Client) Sync(ctx context.Context, req wire.SyncWebhookRequest) (*SyncResult, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("webhooks: sync: request JSON: %w", err)
	}
	resp, err := c.cli.Do(ctx, client.Request{
		Method:     http.MethodPost,
		Path:       "/v1/webhooks/sync",
		Body:       body,
		Auth:       wire.AuthParty,
		Idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	var out wire.SyncWebhookResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("webhooks: sync: %w", err)
	}
	result := &SyncResult{SyncWebhookResponse: &out}
	if raw := resp.Header.Get("X-Quota-Remaining"); raw != "" {
		result.QuotaRemaining = &raw
	}
	return result, nil
}

// Status reads one enqueued invocation's delivery state at GET
// /v1/webhooks/{id}/status (SDK-API-001): the request is signed by the
// client's party signer (AuthParty) and — as a read, not a create —
// sends no Idempotency-Key.
// Parameters: ctx is the call context; webhookID is the enqueued
// invocation to inspect.
// Returns: the decoded WebhookStatusResponse, or an error — a gateway
// failure surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) Status(ctx context.Context, webhookID string) (*wire.WebhookStatusResponse, error) {
	resp, err := c.cli.Do(ctx, client.Request{
		Method: http.MethodGet,
		Path:   "/v1/webhooks/" + url.PathEscape(webhookID) + "/status",
		Auth:   wire.AuthParty,
	})
	if err != nil {
		return nil, err
	}
	var out wire.WebhookStatusResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("webhooks: status: %w", err)
	}
	return &out, nil
}

// Result submits the caller's outcome at POST /v1/webhooks/{id}/result
// (SDK-API-001) with the party-auth path of the two-class result route:
// the request is signed by the client's party signer (AuthParty) and
// carries an Idempotency-Key (the row requires one, SDK-API-002).
// Parameters: ctx is the call context; webhookID is the enqueued
// invocation; req carries the outcome string.
// Returns: the decoded WebhookResultResponse (202 "accepted"), or an
// error — a gateway failure surfaces as *wire.Error (SDK-CLIENT-003).
// Never panics.
func (c *Client) Result(ctx context.Context, webhookID string, req wire.WebhookResultRequest) (*wire.WebhookResultResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("webhooks: result: request JSON: %w", err)
	}
	resp, err := c.cli.Do(ctx, client.Request{
		Method:     http.MethodPost,
		Path:       "/v1/webhooks/" + url.PathEscape(webhookID) + "/result",
		Body:       body,
		Auth:       wire.AuthParty,
		Idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	var out wire.WebhookResultResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("webhooks: result: %w", err)
	}
	return &out, nil
}
