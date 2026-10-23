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

// TestCodeCatalogLookup asserts a lookup by GW-* code returns the
// entry with its normative HTTP status and disposition: the eight
// hardening codes plus the two codes backed by sentinels
// (SDK-WIRE-003). The two sentinel-backed rows must agree with the
// sentinel's own status so errors.Is/As and the catalog cannot drift.
func TestCodeCatalogLookup(t *testing.T) {
	cases := []struct {
		code        string
		status      int
		disposition wire.Disposition
	}{
		{code: "GW-PARTY-010", status: http.StatusForbidden, disposition: wire.DispositionFixRequest},
		{code: "GW-PARTY-011", status: http.StatusForbidden, disposition: wire.DispositionFixRequest},
		{code: "GW-HOOK-006", status: http.StatusPaymentRequired, disposition: wire.DispositionStop},
		{code: "GW-HOOK-008", status: http.StatusUnprocessableEntity, disposition: wire.DispositionFixRequest},
		{code: "GW-HOOK-009", status: http.StatusServiceUnavailable, disposition: wire.DispositionRetry},
		{code: "GW-RATE-001", status: http.StatusTooManyRequests, disposition: wire.DispositionRetry},
		{code: "GW-IDX-011", status: http.StatusTooManyRequests, disposition: wire.DispositionRetry},
		{code: "GW-STS-005", status: http.StatusTooManyRequests, disposition: wire.DispositionRetry},
		{code: wire.CodeIdempotencyInProgressGateway, status: http.StatusConflict, disposition: wire.DispositionRetry},
		{code: wire.CodeInvalidEnrollmentToken, status: http.StatusUnauthorized, disposition: wire.DispositionFixRequest},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			entry, ok := wire.LookupCode(tc.code)
			require.True(t, ok, "LookupCode(%q) missed", tc.code)
			assert.Equal(t, tc.code, entry.Code)
			assert.Equal(t, tc.status, entry.Status)
			assert.Equal(t, tc.disposition, entry.Disposition)
		})
	}

	api002, ok := wire.LookupCode(wire.CodeIdempotencyInProgressGateway)
	require.True(t, ok)
	assert.Equal(t, wire.ErrIdempotencyInProgress.Status, api002.Status)
	party007, ok := wire.LookupCode(wire.CodeInvalidEnrollmentToken)
	require.True(t, ok)
	assert.Equal(t, wire.ErrInvalidEnrollmentToken.Status, party007.Status)
}

// TestCodeCatalogComplete enumerates the gateway Error catalog
// (Bruno opencollection.yml §Error catalog) row for row: status and
// disposition literals are transcribed from the normative table. The
// catalog exposed by wire must contain exactly these rows — a code
// added to, dropped from, or changed in the gateway table fails here
// until the SDK catalog is updated (SDK-WIRE-003).
func TestCodeCatalogComplete(t *testing.T) {
	const (
		retry  = wire.DispositionRetry
		fix    = wire.DispositionFixRequest
		stop   = wire.DispositionStop
		reauth = wire.DispositionReAuthenticate
	)
	want := map[string]struct {
		status int
		disp   wire.Disposition
	}{
		// GW-PARTY — Registry/Resolver plane
		"GW-PARTY-001": {404, fix},
		"GW-PARTY-002": {403, stop},
		"GW-PARTY-003": {409, fix},
		"GW-PARTY-004": {400, fix},
		"GW-PARTY-005": {404, fix},
		"GW-PARTY-006": {409, fix},
		"GW-PARTY-007": {401, fix},
		"GW-PARTY-008": {403, fix},
		"GW-PARTY-009": {502, retry},
		"GW-PARTY-010": {403, fix},
		"GW-PARTY-011": {403, fix},
		// GW-IDX — Identity plane
		"GW-IDX-001": {400, fix},
		"GW-IDX-002": {404, fix},
		"GW-IDX-010": {404, fix},
		"GW-IDX-011": {429, retry},
		// GW-STS — Ticket/Approval plane
		"GW-STS-001": {400, fix},
		"GW-STS-002": {410, stop},
		"GW-STS-003": {403, fix},
		"GW-STS-004": {403, fix},
		"GW-STS-005": {429, retry},
		// GW-PAY — Money plane
		"GW-PAY-001": {500, retry},
		"GW-PAY-002": {404, fix},
		"GW-PAY-003": {401, stop},
		"GW-PAY-004": {404, fix},
		"GW-PAY-005": {404, fix},
		"GW-PAY-006": {400, fix},
		"GW-PAY-007": {502, retry},
		// GW-HOOK — Integration plane
		"GW-HOOK-001": {404, fix},
		"GW-HOOK-002": {500, retry},
		"GW-HOOK-003": {502, retry},
		"GW-HOOK-004": {404, fix},
		"GW-HOOK-005": {504, retry},
		"GW-HOOK-006": {402, stop},
		"GW-HOOK-007": {401, reauth},
		"GW-HOOK-008": {422, fix},
		"GW-HOOK-009": {503, retry},
		// GW-ADMIN — Operator plane
		"GW-ADMIN-001": {401, reauth},
		"GW-ADMIN-002": {400, fix},
		"GW-ADMIN-003": {429, retry},
		"GW-ADMIN-004": {401, reauth},
		"GW-ADMIN-005": {401, reauth},
		// GW-API — Cross-cutting transport
		"GW-API-001": {413, fix},
		"GW-API-002": {409, retry},
		"GW-API-003": {500, retry},
		// GW-RATE — Rate limiting
		"GW-RATE-001": {429, retry},
	}

	got := wire.Codes()
	require.Len(t, got, len(want))
	seen := make(map[string]bool, len(want))
	for _, entry := range got {
		exp, ok := want[entry.Code]
		require.True(t, ok, "unexpected catalog entry %q", entry.Code)
		require.False(t, seen[entry.Code], "duplicate catalog entry %q", entry.Code)
		seen[entry.Code] = true
		assert.Equal(t, exp.status, entry.Status, "status of %s", entry.Code)
		assert.Equal(t, exp.disp, entry.Disposition, "disposition of %s", entry.Code)
		lu, ok := wire.LookupCode(entry.Code)
		require.True(t, ok, "LookupCode(%q) missed", entry.Code)
		assert.Equal(t, entry, lu)
	}
}

// TestCodeCatalogUnknownAndFresh asserts an unknown code misses the
// catalog (false, zero entry) and Codes() hands out a copy: mutating
// the returned slice must not corrupt later lookups (SDK-WIRE-003).
func TestCodeCatalogUnknownAndFresh(t *testing.T) {
	for _, code := range []string{"", "GW-NOPE-001", "GW-PARTY-0100", "not-a-code"} {
		entry, ok := wire.LookupCode(code)
		assert.False(t, ok, "LookupCode(%q) must miss", code)
		assert.Equal(t, wire.CodeEntry{}, entry)
	}

	all := wire.Codes()
	require.NotEmpty(t, all)
	orig := all[0]
	all[0] = wire.CodeEntry{Code: "GW-FUTURE-999", Status: 599, Disposition: wire.DispositionRetry}
	_, ok := wire.LookupCode("GW-FUTURE-999")
	assert.False(t, ok, "mutating Codes() result leaked into the catalog")
	_, ok = wire.LookupCode(orig.Code)
	assert.True(t, ok, "Codes() mutation disturbed a real entry")
}

// TestRetryClassification follows the gateway Error catalog
// disposition, including the hardening codes (SDK-RETRY-002/003):// a code whose disposition is "retry" is retryable, every other
// disposition is terminal. A code the catalog does not define falls
// back to status-based classification (the SDK-RETRY-002 status set
// 429/502/503/504) instead of erroring.
func TestRetryClassification(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		code      string
		retryable bool
	}{
		// Retryable (SDK-RETRY-002), incl. the hardening codes.
		{"429 GW-RATE-001", http.StatusTooManyRequests, "GW-RATE-001", true},
		{"429 GW-ADMIN-003", http.StatusTooManyRequests, "GW-ADMIN-003", true},
		{"429 GW-IDX-011", http.StatusTooManyRequests, "GW-IDX-011", true},
		{"429 GW-STS-005", http.StatusTooManyRequests, "GW-STS-005", true},
		{"409 GW-API-002", http.StatusConflict, "GW-API-002", true},
		{"502 no code", http.StatusBadGateway, "", true},
		{"503 GW-HOOK-009", http.StatusServiceUnavailable, "GW-HOOK-009", true},
		{"504 no code", http.StatusGatewayTimeout, "", true},
		// Terminal (SDK-RETRY-003).
		{"400 no code", http.StatusBadRequest, "", false},
		{"401 no code", http.StatusUnauthorized, "", false},
		{"402 GW-HOOK-006", http.StatusPaymentRequired, "GW-HOOK-006", false},
		{"403 GW-PARTY-011", http.StatusForbidden, "GW-PARTY-011", false},
		{"404 no code", http.StatusNotFound, "", false},
		{"409 GW-PARTY-006", http.StatusConflict, "GW-PARTY-006", false},
		{"413 no code", http.StatusRequestEntityTooLarge, "", false},
		{"413 GW-API-001", http.StatusRequestEntityTooLarge, "GW-API-001", false},
		{"422 GW-HOOK-008", http.StatusUnprocessableEntity, "GW-HOOK-008", false},
		// Unrecognised codes fall back to status, never error.
		{"429 unknown code", http.StatusTooManyRequests, "GW-NOPE-001", true},
		{"503 empty code", http.StatusServiceUnavailable, "", true},
		{"400 junk code", http.StatusBadRequest, "not-a-code", false},
		{"409 unknown code", http.StatusConflict, "GW-NOPE-001", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.retryable, wire.Retryable(tc.status, tc.code))
		})
	}
}

// TestRetryClassificationMatchesCatalog asserts every cataloged code
// classifies exactly by its normative disposition — retryable iff the
// disposition is "retry" — so the catalog and the retry classifier can
// never drift apart (SDK-RETRY-002/003).
func TestRetryClassificationMatchesCatalog(t *testing.T) {
	for _, entry := range wire.Codes() {
		want := entry.Disposition == wire.DispositionRetry
		assert.Equal(t, want, wire.Retryable(entry.Status, entry.Code),
			"code %s must classify by disposition", entry.Code)
	}
}

// TestRetry402RequiresNewIdempotencyKey pins the 402 rule
// (SDK-RETRY-003, ADR-011): a 402 Payment Required is terminal and
// flagged as requiring a fresh Idempotency-Key once payment is
// settled; every other status keeps the key stable across transport
// retries (ADR-008).
func TestRetry402RequiresNewIdempotencyKey(t *testing.T) {
	assert.False(t, wire.Retryable(http.StatusPaymentRequired, "GW-HOOK-006"))
	assert.True(t, wire.RequiresNewIdempotencyKey(http.StatusPaymentRequired, "GW-HOOK-006"))
	// Even an unrecognised 402 code is flagged: the flag is status-based.
	assert.True(t, wire.RequiresNewIdempotencyKey(http.StatusPaymentRequired, "GW-NOPE-001"))

	for _, status := range []int{200, 400, 401, 403, 404, 409, 413, 422, 429, 502, 503, 504} {
		assert.False(t, wire.RequiresNewIdempotencyKey(status, ""),
			"status %d must keep the Idempotency-Key stable", status)
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
