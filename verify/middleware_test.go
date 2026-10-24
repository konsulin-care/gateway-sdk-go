package verify_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/verify"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// mintDelivery mints a well-formed ks-delivery+jwt for the env's frozen
// clock whose body_sha256 covers body and whose webhook_id is id — the
// callback token every middleware test delivers.
func mintDelivery(t *testing.T, env *perKindEnv, id string, body []byte) string {
	t.Helper()
	claims := deliveryClaims(env.now, perKindSelf, string(body))
	claims["webhook_id"] = id
	return env.mint(t, wire.TypDelivery, claims)
}

// newCallbackRequest builds a callback request carrying the Bearer token
// (skipped when empty), the exact body bytes, and any extra headers such
// as webhook-id.
func newCallbackRequest(token string, body []byte, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/callback", bytes.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// countingReader counts the bytes streamed out of the source body, so the
// buffer test can prove the middleware makes exactly one pass over the
// original request stream.
type countingReader struct {
	src io.Reader
	n   int64
}

// Read forwards to the source and accumulates the byte count.
func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.n += int64(n)
	return n, err
}

// TestMiddlewareBuffersBodyOnce asserts the accept path of SDK-VERIFY-003:
// a valid request reaches the handler exactly once, the original body is
// streamed exactly once (byte-exact — body_sha256 verified over those
// bytes), the handler's r.Body carries those exact bytes, and
// ClaimsFromContext exposes the verified claims.
func TestMiddlewareBuffersBodyOnce(t *testing.T) {
	env := newPerKindEnv(t, perKindSelf)
	body := []byte(`{"event":"payment.paid","amount":42}`)
	tok := mintDelivery(t, env, "wh-mw-buffer", body)

	src := &countingReader{src: bytes.NewReader(body)}
	req := httptest.NewRequest(http.MethodPost, "/callback", src)
	req.Header.Set("Authorization", "Bearer "+tok)

	var calls int
	var gotClaims verify.Claims
	var handlerBody []byte
	h := verify.Middleware(env.v, wire.TypDelivery)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		gotClaims = verify.ClaimsFromContext(r.Context())
		var err error
		handlerBody, err = io.ReadAll(r.Body)
		require.NoError(t, err, "the handler must read the buffered body")
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code, "the valid request must reach the handler's response")
	assert.Equal(t, 1, calls, "the handler must run exactly once")
	assert.Equal(t, int64(len(body)), src.n,
		"the original body stream must be read exactly once, byte-exact")
	assert.Equal(t, body, handlerBody, "the handler must see the byte-exact body")
	assert.Equal(t, wire.TypDelivery, gotClaims.Typ, "ClaimsFromContext must expose the verified typ")
	assert.Equal(t, "wh-mw-buffer", gotClaims.WebhookID, "ClaimsFromContext must expose the webhook_id claim")
	assert.Equal(t, []string{perKindSelf}, gotClaims.Audience, "ClaimsFromContext must expose the verified audience")
	assert.Equal(t, wire.PurposeWebhookDelivery, gotClaims.Purpose, "ClaimsFromContext must expose the purpose")
}

// TestMiddlewareReplayNeverReachesHandler asserts the replay contract of
// SDK-VERIFY-003: the first delivery with a webhook_id reaches the handler,
// the second delivery of the same webhook_id answers 200 with an empty body
// (the gateway treats non-429 4xx as terminal failure) and never touches
// the handler.
func TestMiddlewareReplayNeverReachesHandler(t *testing.T) {
	env := newPerKindEnv(t, perKindSelf)
	body := []byte(`{"event":"payment.paid"}`)
	tok := mintDelivery(t, env, "wh-mw-replay", body)

	var calls int
	h := verify.Middleware(env.v, wire.TypDelivery)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRecorder()
	h.ServeHTTP(first, newCallbackRequest(tok, body, nil))
	assert.Equal(t, http.StatusNoContent, first.Code, "the fresh webhook_id must reach the handler")
	assert.Equal(t, 1, calls)

	// The gateway re-mints a delivery token per retry with the same
	// webhook_id; even the identical token must dedupe the same way.
	retry := mintDelivery(t, env, "wh-mw-replay", body)
	second := httptest.NewRecorder()
	h.ServeHTTP(second, newCallbackRequest(retry, body, nil))
	assert.Equal(t, http.StatusOK, second.Code,
		"a replay must answer 200 so the gateway treats the delivery as done")
	assert.Empty(t, second.Body.String(), "the replay response must carry an empty body")
	assert.Equal(t, 1, calls, "a replayed webhook_id must never reach the handler")
}

// TestMiddlewareDeniesMissingOrInvalidBearer asserts every bearer failure
// denies with 401 before the handler runs: a missing Authorization header,
// a different scheme, empty credentials, and a malformed token.
func TestMiddlewareDeniesMissingOrInvalidBearer(t *testing.T) {
	env := newPerKindEnv(t, perKindSelf)
	body := []byte(`{"k":"v"}`)
	tok := mintDelivery(t, env, "wh-mw-bearer", body)

	var calls int
	h := verify.Middleware(env.v, wire.TypDelivery)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
	}))

	cases := map[string]func(r *http.Request){
		"missing header": func(r *http.Request) { r.Header.Del("Authorization") },
		"wrong scheme":   func(r *http.Request) { r.Header.Set("Authorization", "Basic dXNlcjpwYXNz") },
		"empty token":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
		"malformed jwt":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer not-a-jws") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := newCallbackRequest(tok, body, nil)
			mutate(req)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code, "a bearer failure must deny 401")
			assert.Zero(t, calls, "a denied request must never reach the handler")
		})
	}
}

// TestMiddlewareWebhookIDHeaderMustMatchClaim asserts the transport-header
// rule: a present webhook-id header that disagrees with the webhook_id
// claim denies 401 before the handler, while a matching header passes it.
func TestMiddlewareWebhookIDHeaderMustMatchClaim(t *testing.T) {
	env := newPerKindEnv(t, perKindSelf)
	body := []byte(`{"k":"v"}`)
	tok := mintDelivery(t, env, "wh-mw-header", body)

	var calls int
	h := verify.Middleware(env.v, wire.TypDelivery)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))

	mismatch := httptest.NewRecorder()
	h.ServeHTTP(mismatch, newCallbackRequest(tok, body, map[string]string{"webhook-id": "wh-someone-else"}))
	assert.Equal(t, http.StatusUnauthorized, mismatch.Code,
		"a webhook-id header contradicting the claim must deny 401")
	assert.Zero(t, calls, "a mismatched webhook-id must never reach the handler")

	match := httptest.NewRecorder()
	h.ServeHTTP(match, newCallbackRequest(tok, body, map[string]string{"webhook-id": "wh-mw-header"}))
	assert.Equal(t, http.StatusNoContent, match.Code, "a matching webhook-id header must pass")
	assert.Equal(t, 1, calls)
}

// TestMiddlewareBodyOverLimitDenies asserts a body larger than the
// configured cap denies with 413 before any token work; the handler is
// never called.
func TestMiddlewareBodyOverLimitDenies(t *testing.T) {
	env := newPerKindEnv(t, perKindSelf)
	body := []byte(strings.Repeat("a", 64))
	tok := mintDelivery(t, env, "wh-mw-toobig", body)

	var calls int
	h := verify.Middleware(env.v, wire.TypDelivery, verify.WithMaxBodyBytes(16))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newCallbackRequest(tok, body, nil))
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code,
		"a body over the cap must deny 413")
	assert.Zero(t, calls, "an over-limit body must never reach the handler")
}

// TestMiddlewareReleasesReservationOn5xx asserts a handler that responds
// 5xx releases its webhook_id reservation, so the gateway's retry of the
// same delivery reaches the handler instead of being deduped.
func TestMiddlewareReleasesReservationOn5xx(t *testing.T) {
	env := newPerKindEnv(t, perKindSelf)
	body := []byte(`{"k":"v"}`)
	tok := mintDelivery(t, env, "wh-mw-5xx", body)

	var calls int
	h := verify.Middleware(env.v, wire.TypDelivery)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))

	first := httptest.NewRecorder()
	h.ServeHTTP(first, newCallbackRequest(tok, body, nil))
	assert.Equal(t, http.StatusInternalServerError, first.Code)
	assert.Equal(t, 1, calls)

	retry := httptest.NewRecorder()
	h.ServeHTTP(retry, newCallbackRequest(tok, body, nil))
	assert.Equal(t, http.StatusInternalServerError, retry.Code)
	assert.Equal(t, 2, calls, "after a 5xx the released reservation must let the retry reach the handler")
}

// TestMiddlewareReleasesReservationOnPanic asserts a panicking handler
// releases its webhook_id reservation and the panic is re-raised unchanged;
// a later retry of the same delivery then reaches the handler.
func TestMiddlewareReleasesReservationOnPanic(t *testing.T) {
	env := newPerKindEnv(t, perKindSelf)
	body := []byte(`{"k":"v"}`)
	tok := mintDelivery(t, env, "wh-mw-panic", body)

	var calls int
	panicking := true
	h := verify.Middleware(env.v, wire.TypDelivery)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if panicking {
			panic("handler boom")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRecorder()
	assert.Panics(t, func() { h.ServeHTTP(first, newCallbackRequest(tok, body, nil)) },
		"a handler panic must be re-raised, not swallowed")
	assert.Equal(t, 1, calls)

	panicking = false
	retry := httptest.NewRecorder()
	h.ServeHTTP(retry, newCallbackRequest(tok, body, nil))
	assert.Equal(t, http.StatusNoContent, retry.Code)
	assert.Equal(t, 2, calls, "after a panic the released reservation must let the retry reach the handler")
}

// TestClaimsFromContextZeroWithoutMiddleware asserts a context that never
// passed through the middleware yields the zero Claims, never a panic.
func TestClaimsFromContextZeroWithoutMiddleware(t *testing.T) {
	assert.Equal(t, verify.Claims{}, verify.ClaimsFromContext(context.Background()))
}
