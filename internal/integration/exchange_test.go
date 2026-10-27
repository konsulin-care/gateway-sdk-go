package integration

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/approvals"
	"github.com/konsulin-care/gateway-sdk-go/envelope"
	"github.com/konsulin-care/gateway-sdk-go/gatewaytest"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// runExchangeFlow covers the exchange flow of SDK-TEST-002:
// approvals.Mint returns a ticket that the recipient's six-rule check
// (verify.Ticket) accepts, and envelope.Seal to the recipient's use:enc
// key followed by envelope.Open returns byte-identical plaintext.
//
// Parameters: t is the subtest; fx is the shared fixture.
func runExchangeFlow(t *testing.T, fx *fixture) {
	t.Helper()
	ctx := context.Background()

	t.Run("Mint returns a ticket the six-rule check accepts", func(t *testing.T) {
		now := time.Now()
		jti := "jti-integration-approval-001"
		ticket, err := fx.minter.Mint(wire.TypApproval, mustJSON(t, map[string]any{
			"iss":             "gateway",
			"aud":             recipientPartyID,
			"sub":             testPartyID,
			"scope":           "referral",
			"purpose":         "referral to study",
			"researcher_hash": "N/A",
			"jti":             jti,
			"iat":             now.Add(-time.Minute).Unix(),
			"exp":             now.Add(10 * time.Minute).Unix(),
		}))
		require.NoError(t, err)

		fx.g.Script(http.MethodPost, "/v1/approvals", gatewaytest.ScriptStep{
			Status: http.StatusOK,
			Body: mustJSON(t, wire.MintApprovalResponse{
				AccessToken: ticket,
				JTI:         jti,
				ExpiresAt:   now.Add(10 * time.Minute).UTC().Format(time.RFC3339),
			}),
		})
		ac, err := approvals.New(fx.cli)
		require.NoError(t, err)
		out, err := ac.Mint(ctx, wire.MintApprovalRequest{
			To:      recipientPartyID,
			Scope:   "referral",
			Purpose: "referral to study",
			TTL:     900,
		})
		require.NoError(t, err, "approvals.Mint must succeed against gatewaytest")
		require.NotNil(t, out)
		assert.Equal(t, ticket, out.AccessToken, "Mint must return the minted ticket")

		claims, err := fx.verifier.Ticket(ctx, out.AccessToken, wire.TypApproval, "referral")
		require.NoError(t, err, "the recipient's six-rule check must accept the ticket")
		assert.Equal(t, []string{recipientPartyID}, claims.Audience)
		assert.Equal(t, "referral", claims.Scope)
		assert.Equal(t, jti, claims.JTI)
	})

	t.Run("Seal to the recipient use:enc key opens byte-identical", func(t *testing.T) {
		recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		x := base64.RawURLEncoding.EncodeToString(recipient.PublicKey().Bytes())
		kid := rfc7638Thumbprint(t, "OKP", "X25519", x)
		jwks := mustJSON(t, map[string]any{"keys": []map[string]any{{
			"kty": "OKP", "crv": "X25519", "use": "enc", "kid": kid, "x": x,
		}}})

		encKey, err := envelope.SelectEncKey(jwks, kid)
		require.NoError(t, err, "the recipient use:enc key must be selectable by kid")
		plaintext := []byte(`{"study":"cohort-a","rows":42}`)
		compact, err := envelope.Seal(plaintext, kid, encKey)
		require.NoError(t, err)
		opened, err := envelope.Open(compact, recipient)
		require.NoError(t, err, "the recipient must open its own envelope")
		assert.Equal(t, plaintext, opened, "Open must return byte-identical plaintext")
	})
}
