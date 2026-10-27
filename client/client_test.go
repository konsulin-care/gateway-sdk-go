package client_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// newTransportClient builds a Client over the given stub transport with an
// auth-public default so no signer is required. Parameters: t — the test;
// rt — the stubbed transport. Returns: the constructed Client.
func newTransportClient(t *testing.T, rt client.RoundTripFunc) *client.Client {
	t.Helper()
	c, err := client.New(
		client.WithBaseURL("https://gw.example"),
		client.WithHTTPClient(&http.Client{Transport: rt}),
		client.WithLogger(client.NewLogCapture().Logger()),
	)
	require.NoError(t, err, "a minimal client must construct")
	require.NotNil(t, c)
	return c
}

// TestClientSurfacesWireErrorFromResponse covers SDK-CLIENT-003: a non-2xx
// gateway error envelope surfaces as *wire.Error with Code, Message,
// RequestID and Status preserved verbatim, and no Response alongside it.
func TestClientSurfacesWireErrorFromResponse(t *testing.T) {
	const body = `{"error":{"code":"capability_denied","message":"party lacks the required capability","request_id":"req_err_1"}}`
	c := newTransportClient(t, func(r *http.Request) (*http.Response, error) {
		header := http.Header{}
		header.Set("X-Request-Id", "req_err_1")
		return stubResponse(r, http.StatusForbidden, header, body), nil
	})

	resp, err := c.Do(context.Background(), client.Request{
		Method: http.MethodGet,
		Path:   "/v1/things",
		Auth:   wire.AuthPublic,
	})
	require.Error(t, err, "a non-2xx must surface as an error, never a success")
	assert.Nil(t, resp, "a failed call returns no response")

	var gwErr *wire.Error
	require.ErrorAs(t, err, &gwErr, "the error must be a *wire.Error")
	assert.Equal(t, wire.CodeCapabilityDenied, gwErr.Code)
	assert.Equal(t, "party lacks the required capability", gwErr.Message)
	assert.Equal(t, "req_err_1", gwErr.RequestID)
	assert.Equal(t, http.StatusForbidden, gwErr.Status)
}

// TestClientErrorMatchesCatalogSentinel asserts errors.Is matches the
// catalog sentinel for the code the client surfaced (SDK-CLIENT-003):
// capability_denied compares against wire.ErrCapabilityDenied by code.
func TestClientErrorMatchesCatalogSentinel(t *testing.T) {
	const body = `{"error":{"code":"capability_denied","message":"missing grant","request_id":"req_err_2"}}`
	c := newTransportClient(t, func(r *http.Request) (*http.Response, error) {
		return stubResponse(r, http.StatusForbidden, nil, body), nil
	})

	_, err := c.Do(context.Background(), client.Request{
		Method: http.MethodGet,
		Path:   "/v1/things",
		Auth:   wire.AuthPublic,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, wire.ErrCapabilityDenied,
		"errors.Is must match the catalog sentinel for the returned code")
}

// TestClientNonEnvelopeErrorHasStatusNoCode covers the SDK-CLIENT-003 deny:
// a non-envelope non-2xx body (a proxy HTML page) never panics and never
// fabricates a code — the *wire.Error carries the HTTP status, an empty
// Code and no RequestID, so it matches no catalog sentinel (fail closed).
func TestClientNonEnvelopeErrorHasStatusNoCode(t *testing.T) {
	c := newTransportClient(t, func(r *http.Request) (*http.Response, error) {
		return stubResponse(r, http.StatusBadGateway, nil, "<html><body>502 Bad Gateway</body></html>"), nil
	})

	resp, err := c.Do(context.Background(), client.Request{
		Method: http.MethodGet,
		Path:   "/v1/things",
		Auth:   wire.AuthPublic,
	})
	require.Error(t, err, "a non-envelope non-2xx must still error, not panic")
	assert.Nil(t, resp)

	var gwErr *wire.Error
	require.ErrorAs(t, err, &gwErr, "a non-envelope body still surfaces as *wire.Error")
	assert.Equal(t, http.StatusBadGateway, gwErr.Status)
	assert.Empty(t, gwErr.Code, "a non-envelope body must never fabricate a code")
	assert.Empty(t, gwErr.RequestID)
	assert.Contains(t, gwErr.Message, "502 Bad Gateway",
		"a bounded hint of the raw body is kept as the message")

	assert.NotErrorIs(t, err, wire.ErrCapabilityDenied)
	assert.NotErrorIs(t, err, wire.ErrIdempotencyInProgress)
	assert.NotErrorIs(t, err, wire.ErrInvalidEnrollmentToken,
		"an empty code matches no catalog sentinel (fail closed)")
}

// TestDecodeIntoIgnoresUnknownFields covers SDK-WIRE-004 at the client
// level: a 2xx response carrying unknown fields decodes into the DTO with
// the known fields intact — forward compatibility never fails the decode.
func TestDecodeIntoIgnoresUnknownFields(t *testing.T) {
	const body = `{"party_id":"party-9","kid":"kid-1","future_field":{"nested":[1,2,3]}}`
	c := newTransportClient(t, func(r *http.Request) (*http.Response, error) {
		return stubResponse(r, http.StatusOK, nil, body), nil
	})

	resp, err := c.Do(context.Background(), client.Request{
		Method: http.MethodPost,
		Path:   "/v1/parties/party-9/enroll",
		Body:   []byte(`{"enrollment_token":"t","public_key":"pk","kid":"kid-1"}`),
		Auth:   wire.AuthPublic,
	})
	require.NoError(t, err, "a 2xx must succeed regardless of unknown fields")
	require.NotNil(t, resp)

	var dto wire.EnrollPartyResponse
	require.NoError(t, client.DecodeInto(resp, &dto),
		"unknown JSON fields must never fail the decode (SDK-WIRE-004)")
	assert.Equal(t, "party-9", dto.PartyID, "known fields keep their values")
	assert.Equal(t, "kid-1", dto.Kid)
}

// TestWithResponseMetaOnSuccess asserts WithResponseMeta captures status,
// request_id and headers when the call succeeds.
func TestWithResponseMetaOnSuccess(t *testing.T) {
	header := http.Header{}
	header.Set("X-Request-Id", "req_meta_ok")
	header.Set("X-Trace-Id", "trace-7")
	c := newTransportClient(t, func(r *http.Request) (*http.Response, error) {
		return stubResponse(r, http.StatusOK, header, `{"ok":true}`), nil
	})

	var captured []client.ResponseMeta
	resp, err := c.Do(context.Background(), client.Request{
		Method: http.MethodGet,
		Path:   "/health",
		Auth:   wire.AuthPublic,
	}, client.WithResponseMeta(func(m client.ResponseMeta) {
		captured = append(captured, m)
	}))
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Len(t, captured, 1, "exactly one completed response must be captured")
	m := captured[0]
	assert.Equal(t, http.StatusOK, m.Status)
	assert.Equal(t, "req_meta_ok", m.RequestID)
	require.NotNil(t, m.Header)
	assert.Equal(t, "trace-7", m.Header.Get("X-Trace-Id"),
		"the captured meta carries the response headers")
}

// TestWithResponseMetaOnFailure asserts WithResponseMeta still captures
// status, request_id and headers when the call fails with *wire.Error —
// a caller can correlate a failed call without the response body.
func TestWithResponseMetaOnFailure(t *testing.T) {
	const body = `{"error":{"code":"GW-PARTY-007","message":"invalid enrollment token","request_id":"req_meta_bad"}}`
	header := http.Header{}
	header.Set("X-Request-Id", "req_meta_bad")
	header.Set("X-Trace-Id", "trace-9")
	c := newTransportClient(t, func(r *http.Request) (*http.Response, error) {
		return stubResponse(r, http.StatusUnauthorized, header, body), nil
	})

	var captured []client.ResponseMeta
	resp, err := c.Do(context.Background(), client.Request{
		Method: http.MethodPost,
		Path:   "/v1/parties/party-1/enroll",
		Auth:   wire.AuthPublic,
	}, client.WithResponseMeta(func(m client.ResponseMeta) {
		captured = append(captured, m)
	}))
	require.Error(t, err, "the 401 must surface as an error")
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, wire.ErrInvalidEnrollmentToken)

	require.Len(t, captured, 1, "a failed call must still capture the response meta")
	m := captured[0]
	assert.Equal(t, http.StatusUnauthorized, m.Status)
	assert.Equal(t, "req_meta_bad", m.RequestID)
	require.NotNil(t, m.Header)
	assert.Equal(t, "trace-9", m.Header.Get("X-Trace-Id"))
}
