package wire_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// TestDecodeErrorEnvelope decodes a literal gateway error envelope
// ({error:{code,message,request_id}}, pkg/errors/response.go WriteError)
// and asserts every *wire.Error field, including the HTTP status
// supplied by the caller (SDK-WIRE-003).
func TestDecodeErrorEnvelope(t *testing.T) {
	body := []byte(`{"error":{"code":"capability_denied","message":"party lacks the required capability","request_id":"req_01J9ZQ8K5V7X2M"}}`)

	err := wire.DecodeError(http.StatusForbidden, body)
	require.IsType(t, (*wire.Error)(nil), err)
	require.NotNil(t, err)

	assert.Equal(t, "capability_denied", err.Code)
	assert.Equal(t, "party lacks the required capability", err.Message)
	assert.Equal(t, "req_01J9ZQ8K5V7X2M", err.RequestID)
	assert.Equal(t, http.StatusForbidden, err.Status)

	// The decoded envelope matches its own catalog sentinel.
	assert.True(t, errors.Is(err, wire.ErrCapabilityDenied))
}

// TestDecodeErrorCatalogCodes asserts the catalog code literals
// verbatim: PRD §9.7 names idempotency_in_progress while the gateway's
// current wire code for the same condition is GW-API-002 (alias).
func TestDecodeErrorCatalogCodes(t *testing.T) {
	assert.Equal(t, "capability_denied", wire.CodeCapabilityDenied)
	assert.Equal(t, "idempotency_in_progress", wire.CodeIdempotencyInProgress)
	assert.Equal(t, "GW-API-002", wire.CodeIdempotencyInProgressGateway)
	assert.Equal(t, "GW-PARTY-007", wire.CodeInvalidEnrollmentToken)

	require.NotNil(t, wire.ErrCapabilityDenied)
	require.NotNil(t, wire.ErrIdempotencyInProgress)
	require.NotNil(t, wire.ErrInvalidEnrollmentToken)
	assert.Equal(t, wire.CodeCapabilityDenied, wire.ErrCapabilityDenied.Code)
	assert.Equal(t, wire.CodeIdempotencyInProgress, wire.ErrIdempotencyInProgress.Code)
	assert.Equal(t, wire.CodeInvalidEnrollmentToken, wire.ErrInvalidEnrollmentToken.Code)
}

// TestErrorsIsSentinels decodes one envelope per catalog code and
// asserts errors.Is matches the right sentinel (including the
// GW-API-002 alias of idempotency_in_progress) and no other
// (SDK-WIRE-003).
func TestErrorsIsSentinels(t *testing.T) {
	cases := []struct {
		name     string
		code     string
		status   int
		sentinel *wire.Error
		other    *wire.Error
	}{
		{
			name:     "capability_denied",
			code:     "capability_denied",
			status:   http.StatusForbidden,
			sentinel: wire.ErrCapabilityDenied,
			other:    wire.ErrInvalidEnrollmentToken,
		},
		{
			name:     "idempotency_in_progress (PRD name)",
			code:     "idempotency_in_progress",
			status:   http.StatusConflict,
			sentinel: wire.ErrIdempotencyInProgress,
			other:    wire.ErrCapabilityDenied,
		},
		{
			name:     "GW-API-002 (gateway wire alias)",
			code:     "GW-API-002",
			status:   http.StatusConflict,
			sentinel: wire.ErrIdempotencyInProgress,
			other:    wire.ErrCapabilityDenied,
		},
		{
			name:     "GW-PARTY-007",
			code:     "GW-PARTY-007",
			status:   http.StatusUnauthorized,
			sentinel: wire.ErrInvalidEnrollmentToken,
			other:    wire.ErrCapabilityDenied,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(fmt.Sprintf(
				`{"error":{"code":%q,"message":"boom","request_id":"req_1"}}`,
				tc.code,
			))
			err := wire.DecodeError(tc.status, body)
			require.NotNil(t, err)

			require.True(t, errors.Is(err, tc.sentinel),
				"errors.Is(%q, %q) = false", err.Code, tc.sentinel.Code)
			assert.False(t, errors.Is(err, tc.other),
				"errors.Is(%q, %q) must be false", err.Code, tc.other.Code)
			assert.Equal(t, tc.status, err.Status)
		})
	}
}

// TestErrorsAsWireError wraps a decoded error in an opaque error and
// asserts errors.As extracts the *wire.Error with code and request_id
// preserved (SDK-WIRE-003 / SDK-CLIENT-003).
func TestErrorsAsWireError(t *testing.T) {
	body := []byte(`{"error":{"code":"GW-PARTY-007","message":"invalid enrollment token","request_id":"req_01J9ZQ"}}`)
	decoded := wire.DecodeError(http.StatusUnauthorized, body)

	wrapped := fmt.Errorf("enroll: %w", decoded)
	var target *wire.Error
	require.True(t, errors.As(wrapped, &target))
	assert.Equal(t, "GW-PARTY-007", target.Code)
	assert.Equal(t, "invalid enrollment token", target.Message)
	assert.Equal(t, "req_01J9ZQ", target.RequestID)
	assert.Equal(t, http.StatusUnauthorized, target.Status)
	assert.True(t, errors.Is(wrapped, wire.ErrInvalidEnrollmentToken))

	var fresh *wire.Error
	require.False(t, errors.As(errors.New("plain"), &fresh))
}

// TestDecodeErrorNonEnvelope asserts a non-envelope body (proxy HTML,
// empty body) still yields a usable *wire.Error carrying the HTTP
// status, with no code — it must match no catalog sentinel (fail
// closed), and DecodeError must never fail or panic.
func TestDecodeErrorNonEnvelope(t *testing.T) {
	bodies := [][]byte{
		nil,
		[]byte("<html><body>502 Bad Gateway</body></html>"),
		[]byte(`{"error":null}`),
		[]byte(`["not","an","object"]`),
	}
	for _, body := range bodies {
		err := wire.DecodeError(http.StatusBadGateway, body)
		require.NotNil(t, err)
		assert.Equal(t, http.StatusBadGateway, err.Status)
		assert.Empty(t, err.Code)
		assert.False(t, errors.Is(err, wire.ErrCapabilityDenied))
		assert.False(t, errors.Is(err, wire.ErrIdempotencyInProgress))
		assert.False(t, errors.Is(err, wire.ErrInvalidEnrollmentToken))
	}
}

// FuzzDecodeError feeds arbitrary status/body pairs to DecodeError and
// asserts it never panics and always returns a usable *wire.Error
// (PRD §14: fuzz targets on error-envelope decoding).
func FuzzDecodeError(f *testing.F) {
	f.Add(http.StatusForbidden, []byte(`{"error":{"code":"capability_denied","message":"m","request_id":"r"}}`))
	f.Add(http.StatusConflict, []byte(`{"error":{"code":"GW-API-002","message":"m","request_id":"r"}}`))
	f.Add(http.StatusUnauthorized, []byte(`{"error":{"code":"GW-PARTY-007","message":"m","request_id":"r"}}`))
	f.Add(0, []byte{})
	f.Add(-1, []byte(`not json`))
	f.Fuzz(func(t *testing.T, status int, body []byte) {
		err := wire.DecodeError(status, body)
		if err == nil {
			t.Fatal("DecodeError returned nil")
		}
		if err.Status != status {
			t.Fatalf("Status = %d, want %d", err.Status, status)
		}
		_ = err.Error()
		_ = errors.Is(err, wire.ErrCapabilityDenied)
	})
}
