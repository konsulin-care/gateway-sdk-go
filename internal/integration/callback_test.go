package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/verify"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// runCallbackFlow covers the callback flow of SDK-TEST-002: a valid
// delivery token passes verify.Middleware and reaches the wrapped
// handler, a second delivery with the same webhook_id is rejected as a
// duplicate without touching the handler, and payment-required and
// service-receipt ks-event+jwt events are accepted by the middleware.
//
// Parameters: t is the subtest; fx is the shared fixture.
func runCallbackFlow(t *testing.T, fx *fixture) {
	t.Helper()
	counter := &callbackCounter{}
	deliver := verify.Middleware(fx.verifier, wire.TypDelivery)(counter)
	event := verify.Middleware(fx.verifier, wire.TypEvent)(counter)
	now := time.Now()

	t.Run("valid delivery reaches the handler", func(t *testing.T) {
		body := []byte(`{"event":"payment.paid","amount":42}`)
		id := "wh-integration-delivery-1"
		tok := mintCallbackToken(t, fx, wire.TypDelivery,
			wire.PurposeWebhookDelivery, id, body, now)

		before, _ := counter.snapshot()
		rec := httptest.NewRecorder()
		deliver.ServeHTTP(rec, callbackRequest(tok, body, id))

		assert.Equal(t, http.StatusNoContent, rec.Code,
			"the valid delivery must reach the handler's response")
		calls, claims := counter.snapshot()
		assert.Equal(t, before+1, calls, "the handler must run once")
		assert.Equal(t, wire.TypDelivery, claims.Typ)
		assert.Equal(t, id, claims.WebhookID)
		assert.Equal(t, []string{recipientPartyID}, claims.Audience)
	})

	t.Run("second delivery with the same webhook_id is a duplicate", func(t *testing.T) {
		body := []byte(`{"event":"payment.paid"}`)
		id := "wh-integration-delivery-dup"
		first := mintCallbackToken(t, fx, wire.TypDelivery,
			wire.PurposeWebhookDelivery, id, body, now)
		// The gateway re-mints a delivery token per retry with the same
		// webhook_id; the replay must dedupe even under a fresh token.
		retry := mintCallbackToken(t, fx, wire.TypDelivery,
			wire.PurposeWebhookDelivery, id, body, now)

		before, _ := counter.snapshot()
		rec := httptest.NewRecorder()
		deliver.ServeHTTP(rec, callbackRequest(first, body, id))
		calls, _ := counter.snapshot()
		assert.Equal(t, before+1, calls, "the first delivery must reach the handler")

		replay := httptest.NewRecorder()
		deliver.ServeHTTP(replay, callbackRequest(retry, body, id))
		assert.Equal(t, http.StatusOK, replay.Code,
			"a duplicate must answer 200 so the gateway stops retrying")
		assert.Empty(t, replay.Body.String(), "a duplicate response must be empty")
		calls, _ = counter.snapshot()
		assert.Equal(t, before+1, calls, "a duplicate webhook_id must never reach the handler")
	})

	t.Run("payment-required and service-receipt events are accepted", func(t *testing.T) {
		for _, purpose := range []string{
			wire.PurposePaymentRequired, wire.PurposeServiceReceipt,
		} {
			body := []byte(`{"event":"` + purpose + `"}`)
			id := "wh-integration-event-" + purpose
			tok := mintCallbackToken(t, fx, wire.TypEvent, purpose, id, body, now)

			before, _ := counter.snapshot()
			rec := httptest.NewRecorder()
			event.ServeHTTP(rec, callbackRequest(tok, body, id))

			assert.Equal(t, http.StatusNoContent, rec.Code,
				"the %s event must be accepted", purpose)
			calls, claims := counter.snapshot()
			assert.Equal(t, before+1, calls, "the %s event must reach the handler", purpose)
			assert.Equal(t, wire.TypEvent, claims.Typ)
			assert.Equal(t, purpose, claims.Purpose)
		}
	})
}

// callbackCounter is the wrapped handler: it records how often it ran and
// the verified claims of the last request. Safe for concurrent use.
type callbackCounter struct {
	mu    sync.Mutex
	calls int
	last  verify.Claims
}

// ServeHTTP records the call and its claims and answers 204.
func (c *callbackCounter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.calls++
	c.last = verify.ClaimsFromContext(r.Context())
	c.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// snapshot returns the call count and the last recorded claims.
func (c *callbackCounter) snapshot() (int, verify.Claims) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, c.last
}

// mintCallbackToken mints a gateway-signed token of typ for one callback:
// iss gateway, aud the recipient, purpose and webhook_id as given, and
// body_sha256 over the exact body bytes.
//
// Parameters: t is the test; fx holds the minter; typ is the token kind;
// purpose is the claim value; webhookID dedupes the delivery; body is
// what body_sha256 covers; now frames iat/exp.
// Returns: the compact token.
func mintCallbackToken(t *testing.T, fx *fixture, typ, purpose, webhookID string,
	body []byte, now time.Time) string {
	t.Helper()
	sum := sha256.Sum256(body)
	payload := mustJSON(t, map[string]any{
		"iss":         "gateway",
		"aud":         recipientPartyID,
		"sub":         testPartyID,
		"purpose":     purpose,
		"webhook_id":  webhookID,
		"body_sha256": base64.RawURLEncoding.EncodeToString(sum[:]),
		"iat":         now.Add(-time.Minute).Unix(),
		"exp":         now.Add(5 * time.Minute).Unix(),
	})
	tok, err := fx.minter.Mint(typ, payload)
	require.NoError(t, err)
	return tok
}

// callbackRequest builds one callback request carrying the Bearer token,
// the exact body bytes, and the webhook-id transport header.
//
// Parameters: token is the compact delivery/event token; body is the
// exact payload; webhookID is the Webhook-Id header value.
// Returns: the request ready for the middleware.
func callbackRequest(token string, body []byte, webhookID string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/callbacks", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Webhook-Id", webhookID)
	return r
}
