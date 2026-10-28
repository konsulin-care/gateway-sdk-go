package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/gatewaytest"
	"github.com/konsulin-care/gateway-sdk-go/listings"
	"github.com/konsulin-care/gateway-sdk-go/payments"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// runSignedCallsFlow covers the signed-calls flow of SDK-TEST-002:
// party-authenticated attempts each carry a distinct jti, a scripted 409
// then 200 replay reuses the one Idempotency-Key of the logical create,
// and a fresh Idempotency-Key is generated only after a terminal 402
// (ADR-011).
//
// Parameters: t is the subtest; fx is the shared fixture.
func runSignedCallsFlow(t *testing.T, fx *fixture) {
	t.Helper()
	ctx := context.Background()
	flowStart := len(fx.g.Recorded())

	t.Run("scripted 409 then 200 reuses the same Idempotency-Key", func(t *testing.T) {
		lc, err := listings.New(fx.cli)
		require.NoError(t, err)
		fx.g.Script(http.MethodPost, "/v1/listings", gatewaytest.ScriptStep{
			Status: http.StatusConflict,
			Body:   errorEnvelope(t, "GW-API-002", "idempotency key still in progress"),
		})

		before := len(fx.g.Recorded())
		_, err = lc.Create(ctx, wire.CreateListingRequest{
			Name:        "Curated pseudonymized research data",
			EndpointURL: "https://clinician.example.com/api/research/access",
			Price:       53200,
		})
		require.NoError(t, err, "409 GW-API-002 then 200 must replay to success")

		recs := fx.g.Recorded()[before:]
		require.Len(t, recs, 2, "the 409 must cost exactly one replay attempt")
		require.NotEmpty(t, recs[0].IdempotencyKey, "the first attempt must send a key")
		assert.Equal(t, recs[0].IdempotencyKey, recs[1].IdempotencyKey,
			"a 409 then 200 replay must reuse the same Idempotency-Key")
		require.NotEmpty(t, recs[0].PartyJTI)
		require.NotEmpty(t, recs[1].PartyJTI)
		assert.NotEqual(t, recs[0].PartyJTI, recs[1].PartyJTI,
			"the replay must sign a fresh jti, never the first attempt's")
	})

	t.Run("a new Idempotency-Key only after a terminal 402", func(t *testing.T) {
		pyc, err := payments.New(fx.cli)
		require.NoError(t, err)
		fx.g.Script(http.MethodPost, "/v1/payments", gatewaytest.ScriptStep{
			Status: http.StatusPaymentRequired,
			Body:   errorEnvelope(t, "GW-HOOK-006", "payment required"),
		})
		req := wire.CreatePaymentRequest{ListingID: "01HZYLISTING000001"}

		before := len(fx.g.Recorded())
		_, err = pyc.Create(ctx, req)
		require.Error(t, err, "the terminal 402 must surface as an error")
		var gwErr *wire.Error
		require.ErrorAs(t, err, &gwErr)
		assert.Equal(t, http.StatusPaymentRequired, gwErr.Status)

		first := fx.g.Recorded()[before:]
		require.Len(t, first, 1, "a terminal 402 must cost exactly one attempt")
		require.NotEmpty(t, first[0].IdempotencyKey)

		_, err = pyc.Create(ctx, req)
		require.NoError(t, err, "the next logical create succeeds")

		all := fx.g.Recorded()[before:]
		require.Len(t, all, 2)
		require.NotEmpty(t, all[1].IdempotencyKey)
		assert.NotEqual(t, all[0].IdempotencyKey, all[1].IdempotencyKey,
			"only a terminal 402 ends the key's life: the next call gets a new key")
	})

	t.Run("every party-authenticated attempt carries a distinct jti", func(t *testing.T) {
		seen := map[string]bool{}
		for _, rec := range fx.g.Recorded()[flowStart:] {
			if rec.Authorization == "" {
				continue
			}
			require.NotEmpty(t, rec.PartyJTI,
				"%s %s must carry a jti", rec.Method, rec.Path)
			require.False(t, seen[rec.PartyJTI],
				"jti %q was used by more than one attempt", rec.PartyJTI)
			seen[rec.PartyJTI] = true
		}
		require.NotEmpty(t, seen, "the flow must have made party-authenticated attempts")
	})
}

// errorEnvelope marshals the gateway error envelope for one catalog code.
//
// Parameters: t is the test; code is the wire code; message is the text.
// Returns: the JSON body bytes.
func errorEnvelope(t *testing.T, code, message string) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{"error": map[string]string{
		"code": code, "message": message, "request_id": "integration",
	}})
}
