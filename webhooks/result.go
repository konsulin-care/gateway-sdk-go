package webhooks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// resultConfig collects the per-call option values of one
// ResultWithTicket call.
type resultConfig struct {
	metaFns []func(client.ResponseMeta)
}

// ResultOption adjusts a single ResultWithTicket call without touching
// Client state; applied per call, e.g. WithResponseMeta. Invalid values
// (nil option, nil callback) fail the call instead of being silently
// ignored.
type ResultOption func(*resultConfig) error

// WithResponseMeta registers fn to receive a client.ResponseMeta for
// the completed result attempt — on success and on failure (as
// *wire.Error or an outcome-unknown error) alike — capturing status,
// request_id, response headers, and the sent Idempotency-Key in the
// captured header.
// Parameters: fn — the capture callback, invoked at most once per call.
// Returns: a ResultOption for ResultWithTicket; a nil fn fails the
// call, never ignored.
func WithResponseMeta(fn func(client.ResponseMeta)) ResultOption {
	return func(rc *resultConfig) error {
		if fn == nil {
			return errors.New("webhooks: WithResponseMeta: callback must not be nil")
		}
		rc.metaFns = append(rc.metaFns, fn)
		return nil
	}
}

// applyResultOptions folds opts into one resultConfig.
// Parameters: opts — the per-call options passed to ResultWithTicket.
// Returns: the collected config, or an error for a nil option or an
// invalid value.
func applyResultOptions(opts []ResultOption) (resultConfig, error) {
	var rc resultConfig
	for _, opt := range opts {
		if opt == nil {
			return resultConfig{}, errors.New("webhooks: nil result option")
		}
		if err := opt(&rc); err != nil {
			return resultConfig{}, err
		}
	}
	return rc, nil
}

// capture invokes every registered meta callback in registration order.
func (rc *resultConfig) capture(meta client.ResponseMeta) {
	for _, fn := range rc.metaFns {
		fn(meta)
	}
}

// ResultWithTicket submits the engine's outcome at POST
// /v1/webhooks/{id}/result over the single-use result-ticket path
// (SDK-API-001, auth:ticket): the Bearer credential is the caller's
// ks-result+jwt ticket, and the call makes exactly one network attempt —
// the route is the engine's terminal step, never retried, whatever the
// client's retry policy says. Each call carries one generated
// Idempotency-Key (SDK-CLIENT-002).
// Parameters: ctx is the call context; webhookID is the enqueued
// invocation; ticket is the single-use result ticket presented verbatim
// as the Bearer credential; req carries the outcome string; opts
// observe the attempt (WithResponseMeta).
// Returns: the decoded WebhookResultResponse (202 "accepted"), or an
// error. A terminal gateway answer (e.g. 401 GW-HOOK-007) surfaces as
// *wire.Error — a known outcome that never matches
// client.ErrOutcomeUnknown. A transport failure, or a retryable status
// (e.g. 503 GW-HOOK-009) after the single attempt, wraps
// client.ErrOutcomeUnknown with the last failure in the chain: the
// operation may or may not have been applied (fail closed, SDK-RETRY-002).
// Never panics.
func (c *Client) ResultWithTicket(ctx context.Context, webhookID, ticket string,
	req wire.WebhookResultRequest, opts ...ResultOption) (*wire.WebhookResultResponse, error) {
	rc, err := applyResultOptions(opts)
	if err != nil {
		return nil, err
	}
	httpReq, key, err := c.buildResultRequest(ctx, webhookID, ticket, req)
	if err != nil {
		return nil, err
	}
	httpResp, err := c.hc.Do(httpReq)
	if err != nil {
		rc.capture(metaWithKey(http.Header{}, key))
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("webhooks: result ticket: aborted: %w", ctxErr)
		}
		return nil, fmt.Errorf("webhooks: result ticket: %w: %w", client.ErrOutcomeUnknown, err)
	}
	defer func() { _ = httpResp.Body.Close() }()
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("webhooks: result ticket: read response body: %w", err)
	}
	return finishResultAttempt(rc, httpResp, body, key)
}

// buildResultRequest constructs the one outbound result-ticket request:
// POST the marshaled outcome at the result path with the ticket as
// "Authorization: Bearer" and the call's generated Idempotency-Key.
// Parameters: ctx — the call context; webhookID — the enqueued
// invocation; ticket — the single-use result ticket; req — the outcome
// DTO, marshaled to JSON.
// Returns: the ready-to-send request, the Idempotency-Key it carries,
// or an error (nil context, missing inputs, request JSON, or URL build).
func (c *Client) buildResultRequest(ctx context.Context, webhookID, ticket string,
	req wire.WebhookResultRequest) (*http.Request, string, error) {
	switch {
	case ctx == nil:
		return nil, "", errors.New("webhooks: nil context")
	case webhookID == "":
		return nil, "", errors.New("webhooks: result ticket: webhook id must not be empty")
	case ticket == "":
		return nil, "", errors.New("webhooks: result ticket: ticket must not be empty")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, "", fmt.Errorf("webhooks: result ticket: request JSON: %w", err)
	}
	key, err := newIdempotencyKey()
	if err != nil {
		return nil, "", err
	}
	target := c.base + "/v1/webhooks/" + url.PathEscape(webhookID) + "/result"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("webhooks: result ticket: build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+ticket)
	httpReq.Header.Set("Idempotency-Key", key)
	httpReq.Header.Set("Content-Type", "application/json")
	return httpReq, key, nil
}

// finishResultAttempt maps the completed single attempt to what
// ResultWithTicket returns: it captures the response meta with the sent
// Idempotency-Key, then a 2xx decodes into the DTO; a retryable status
// exhausts the one-attempt budget and wraps client.ErrOutcomeUnknown
// with the parsed *wire.Error; any other status returns that *wire.Error
// unwrapped — a known outcome.
// Parameters: rc — the call's option config (meta capture); resp — the
// completed HTTP response; body — its buffered body; key — the sent
// Idempotency-Key.
// Returns: the decoded WebhookResultResponse, or the error above.
func finishResultAttempt(rc resultConfig, resp *http.Response, body []byte, key string) (*wire.WebhookResultResponse, error) {
	meta := resp.Header.Clone()
	if meta == nil {
		meta = http.Header{}
	}
	meta.Set("Idempotency-Key", key)
	rc.capture(client.ResponseMeta{Status: resp.StatusCode, RequestID: meta.Get("X-Request-Id"), Header: meta})
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		werr := wire.DecodeError(resp.StatusCode, body)
		if wire.Retryable(resp.StatusCode, werr.Code) {
			return nil, fmt.Errorf("webhooks: result ticket: single attempt exhausted: %w: %w",
				client.ErrOutcomeUnknown, werr)
		}
		return nil, werr
	}
	var out wire.WebhookResultResponse
	if err := client.DecodeInto(&client.Response{StatusCode: resp.StatusCode, Header: meta, Body: body}, &out); err != nil {
		return nil, fmt.Errorf("webhooks: result ticket: %w", err)
	}
	return &out, nil
}

// metaWithKey builds the meta of a call that never completed a
// response: status zero, no request id, and only the generated
// Idempotency-Key in the header — so WithResponseMeta still exposes the
// key on a transport failure.
// Parameters: header — the response header clone (may be empty);
// key — the generated Idempotency-Key.
// Returns: the ResponseMeta handed to the capture callbacks.
func metaWithKey(header http.Header, key string) client.ResponseMeta {
	header.Set("Idempotency-Key", key)
	return client.ResponseMeta{Header: header}
}

// newIdempotencyKey generates one UUIDv4-shaped Idempotency-Key (16
// crypto/rand bytes, version/variant nibbles set, lowercase hex with
// dashes) for one ResultWithTicket call, mirroring the client's
// generated keys. Entropy failure fails the call instead of weakening
// the key (fail closed). Returns: the key, or an error.
func newIdempotencyKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("webhooks: generate idempotency key: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
