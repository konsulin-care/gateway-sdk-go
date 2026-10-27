package client_test

import (
	"context"
	"net/http"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// uuidV4Re matches the generated Idempotency-Key shape: UUIDv4 layout,
// lowercase hex (ADR-011).
var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// hook006Body is the terminal402 error envelope (entitlement quota
// exhausted, SDK-RETRY-003).
const hook006Body = `{"error":{"code":"GW-HOOK-006","message":"entitlement quota exhausted","request_id":"req_402_1"}}`

// newRetryTransportClient builds an auth-public Client over rt with the
// given total attempt budget and zero delays. Parameters: t — the test;
// rt — the stubbed transport; attempts — RetryPolicy.MaxAttempts.
// Returns: the constructed Client.
func newRetryTransportClient(t *testing.T, rt client.RoundTripFunc, attempts int) *client.Client {
	t.Helper()
	c, err := client.New(
		client.WithBaseURL("https://gw.example"),
		client.WithHTTPClient(&http.Client{Transport: rt}),
		client.WithLogger(client.NewLogCapture().Logger()),
		client.WithRetry(client.RetryPolicy{MaxAttempts: attempts}),
	)
	require.NoError(t, err, "a retry client must construct")
	require.NotNil(t, c)
	return c
}

// scriptedStep is one scripted gateway answer: HTTP status plus body.
type scriptedStep struct {
	status int
	body   string
}

// scriptedTransport answers scripted steps in order (the last repeats) and
// records the Idempotency-Key of every attempt.
type scriptedTransport struct {
	steps []scriptedStep
	keys  []string
}

// roundTrip records the key header of this attempt and answers the next
// scripted step, repeating the last one once the script runs out.
func (s *scriptedTransport) roundTrip(r *http.Request) (*http.Response, error) {
	i := len(s.keys)
	s.keys = append(s.keys, r.Header.Get("Idempotency-Key"))
	step := s.steps[min(i, len(s.steps)-1)]
	return stubResponse(r, step.status, nil, step.body), nil
}

// TestIdempotentRequestSendsGeneratedKey covers SDK-CLIENT-002: an
// idempotent request without a caller key sends a generated non-empty
// Idempotency-Key in UUIDv4 layout.
func TestIdempotentRequestSendsGeneratedKey(t *testing.T) {
	var seen *http.Request
	c := newTransportClient(t, func(r *http.Request) (*http.Response, error) {
		seen = r
		return stubResponse(r, http.StatusOK, nil, `{"ok":true}`), nil
	})

	resp, err := c.Do(context.Background(), client.Request{
		Method:     http.MethodPost,
		Path:       "/v1/listings",
		Body:       []byte(`{"amount":10}`),
		Auth:       wire.AuthPublic,
		Idempotent: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, seen)

	key := seen.Header.Get("Idempotency-Key")
	require.NotEmpty(t, key, "an idempotent request without a caller key must send a generated key")
	assert.Regexp(t, uuidV4Re, key, "the generated key must be UUIDv4-shaped")
}

// TestIdempotencyKeyStableAcrossRetries (proving test, docs/tasks/03): one
// logical create answered 503, 503, 200 carries the same generated key on
// every attempt (SDK-RETRY-001, ADR-011).
func TestIdempotencyKeyStableAcrossRetries(t *testing.T) {
	script := &scriptedTransport{steps: []scriptedStep{
		{http.StatusServiceUnavailable, ""},
		{http.StatusServiceUnavailable, ""},
		{http.StatusOK, `{"ok":true}`},
	}}
	c := newRetryTransportClient(t, script.roundTrip, 3)

	resp, err := c.Do(context.Background(), client.Request{
		Method:     http.MethodPost,
		Path:       "/v1/listings",
		Body:       []byte(`{"amount":10}`),
		Auth:       wire.AuthPublic,
		Idempotent: true,
	})
	require.NoError(t, err, "the final 200 must succeed")
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	require.Len(t, script.keys, 3, "each 503 must cost exactly one further attempt")
	require.NotEmpty(t, script.keys[0])
	assert.Equal(t, script.keys[0], script.keys[1], "attempt 2 must reuse the key of attempt 1")
	assert.Equal(t, script.keys[0], script.keys[2], "attempt 3 must reuse the key of attempt 1")
}

// TestSeparateCallsSendDistinctKeys: two separate idempotent calls are two
// logical creates and must never share a generated key.
func TestSeparateCallsSendDistinctKeys(t *testing.T) {
	var keys []string
	c := newTransportClient(t, func(r *http.Request) (*http.Response, error) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		return stubResponse(r, http.StatusOK, nil, `{"ok":true}`), nil
	})
	req := client.Request{
		Method: http.MethodPost, Path: "/v1/listings",
		Body: []byte(`{"amount":10}`), Auth: wire.AuthPublic, Idempotent: true,
	}

	_, err := c.Do(context.Background(), req)
	require.NoError(t, err)
	_, err = c.Do(context.Background(), req)
	require.NoError(t, err)

	require.Len(t, keys, 2)
	assert.NotEmpty(t, keys[0])
	assert.NotEmpty(t, keys[1])
	assert.NotEqual(t, keys[0], keys[1], "two logical creates must carry distinct keys")
}

// Test402ReturnsAfterOneAttempt: 402 GW-HOOK-006 is DispositionStop — the
// call returns after one attempt even under a 3-attempt policy
// (SDK-RETRY-003, ADR-011).
func Test402ReturnsAfterOneAttempt(t *testing.T) {
	script := &scriptedTransport{steps: []scriptedStep{{http.StatusPaymentRequired, hook006Body}}}
	c := newRetryTransportClient(t, script.roundTrip, 3)

	resp, err := c.Do(context.Background(), client.Request{
		Method:     http.MethodPost,
		Path:       "/v1/payments",
		Body:       []byte(`{"amount":10}`),
		Auth:       wire.AuthPublic,
		Idempotent: true,
	})
	require.Error(t, err, "the terminal 402 must surface as an error")
	assert.Nil(t, resp)
	var gwErr *wire.Error
	require.ErrorAs(t, err, &gwErr)
	assert.Equal(t, "GW-HOOK-006", gwErr.Code)
	assert.Equal(t, http.StatusPaymentRequired, gwErr.Status)
	assert.Len(t, script.keys, 1, "a terminal 402 must cost exactly one attempt")
}

// TestNextCallAfter402SendsDifferentKey: the 402 decided the operation's
// outcome, so the next call is a new logical create with a fresh key
// (ADR-011, SDK-RETRY-003).
func TestNextCallAfter402SendsDifferentKey(t *testing.T) {
	script := &scriptedTransport{steps: []scriptedStep{
		{http.StatusPaymentRequired, hook006Body},
		{http.StatusOK, `{"ok":true}`},
	}}
	c := newRetryTransportClient(t, script.roundTrip, 3)
	req := client.Request{
		Method: http.MethodPost, Path: "/v1/payments",
		Body: []byte(`{"amount":10}`), Auth: wire.AuthPublic, Idempotent: true,
	}

	_, err := c.Do(context.Background(), req)
	require.Error(t, err, "the first call ends in the terminal 402")
	_, err = c.Do(context.Background(), req)
	require.NoError(t, err, "the retried call succeeds")

	require.Len(t, script.keys, 2)
	assert.NotEmpty(t, script.keys[0])
	assert.NotEmpty(t, script.keys[1])
	assert.NotEqual(t, script.keys[0], script.keys[1],
		"after a terminal 402 the next call must carry a new key")
}

// TestChangedBodySendsDifferentKey: a changed body is a different operation
// and must never reuse the previous call's key (ADR-011, GW-HOOK-008).
func TestChangedBodySendsDifferentKey(t *testing.T) {
	var keys []string
	c := newTransportClient(t, func(r *http.Request) (*http.Response, error) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		return stubResponse(r, http.StatusOK, nil, `{"ok":true}`), nil
	})

	base := client.Request{Method: http.MethodPost, Path: "/v1/listings", Auth: wire.AuthPublic, Idempotent: true}
	first := base
	first.Body = []byte(`{"amount":10}`)
	second := base
	second.Body = []byte(`{"amount":20}`)

	_, err := c.Do(context.Background(), first)
	require.NoError(t, err)
	_, err = c.Do(context.Background(), second)
	require.NoError(t, err)

	require.Len(t, keys, 2)
	assert.NotEmpty(t, keys[0])
	assert.NotEmpty(t, keys[1])
	assert.NotEqual(t, keys[0], keys[1], "a changed body must carry a new key")
}

// TestCallerIdempotencyKeySentOnEveryAttempt: WithIdempotencyKey sends the
// caller's key verbatim on every attempt — the SDK never rewrites it
// (ADR-011 caller-key rule).
func TestCallerIdempotencyKeySentOnEveryAttempt(t *testing.T) {
	script := &scriptedTransport{steps: []scriptedStep{
		{http.StatusServiceUnavailable, ""},
		{http.StatusServiceUnavailable, ""},
		{http.StatusOK, `{"ok":true}`},
	}}
	c := newRetryTransportClient(t, script.roundTrip, 3)

	req := client.Request{
		Method: http.MethodPost, Path: "/v1/payments",
		Body: []byte(`{"amount":10}`), Auth: wire.AuthPublic,
	}.WithIdempotencyKey("caller-key-7")
	resp, err := c.Do(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Len(t, script.keys, 3, "the script must run all three attempts")
	for i, k := range script.keys {
		assert.Equal(t, "caller-key-7", k, "attempt %d must send the caller key verbatim", i+1)
	}
}

// TestWithResponseMetaReportsSentKey: the captured ResponseMeta Header
// carries the Idempotency-Key that was actually sent — on a successful call
// and on a failed one alike (SDK-CLIENT-002 observability).
func TestWithResponseMetaReportsSentKey(t *testing.T) {
	idemReq := client.Request{
		Method: http.MethodPost, Path: "/v1/listings",
		Body: []byte(`{"amount":10}`), Auth: wire.AuthPublic, Idempotent: true,
	}

	t.Run("success", func(t *testing.T) {
		var sent string
		var captured []client.ResponseMeta
		c := newTransportClient(t, func(r *http.Request) (*http.Response, error) {
			sent = r.Header.Get("Idempotency-Key")
			return stubResponse(r, http.StatusOK, nil, `{"ok":true}`), nil
		})
		opt := client.WithResponseMeta(func(m client.ResponseMeta) {
			captured = append(captured, m)
		})
		_, err := c.Do(context.Background(), idemReq, opt)
		require.NoError(t, err)
		require.NotEmpty(t, sent, "the idempotent call must send a generated key")
		require.Len(t, captured, 1)
		assert.Equal(t, sent, captured[0].Header.Get("Idempotency-Key"),
			"the meta must report the key that was sent")
	})

	t.Run("failure", func(t *testing.T) {
		var sent string
		var captured []client.ResponseMeta
		c := newTransportClient(t, func(r *http.Request) (*http.Response, error) {
			sent = r.Header.Get("Idempotency-Key")
			return stubResponse(r, http.StatusPaymentRequired, nil, hook006Body), nil
		})
		opt := client.WithResponseMeta(func(m client.ResponseMeta) {
			captured = append(captured, m)
		})
		_, err := c.Do(context.Background(), idemReq, opt)
		require.Error(t, err, "the terminal 402 must surface as an error")
		require.NotEmpty(t, sent, "the failing idempotent call must send a generated key")
		require.Len(t, captured, 1)
		assert.Equal(t, sent, captured[0].Header.Get("Idempotency-Key"),
			"a failed call's meta must still report the key that was sent")
	})
}

// TestNonIdempotentRequestSendsNoKey: without Idempotent and without a
// caller key the request carries no Idempotency-Key header at all.
func TestNonIdempotentRequestSendsNoKey(t *testing.T) {
	var seen *http.Request
	c := newTransportClient(t, func(r *http.Request) (*http.Response, error) {
		seen = r
		return stubResponse(r, http.StatusOK, nil, `{"ok":true}`), nil
	})

	_, err := c.Do(context.Background(), client.Request{
		Method: http.MethodGet,
		Path:   "/v1/listings",
		Auth:   wire.AuthPublic,
	})
	require.NoError(t, err)
	require.NotNil(t, seen)
	assert.Empty(t, seen.Header.Get("Idempotency-Key"),
		"a non-idempotent request must send no Idempotency-Key header")
}
