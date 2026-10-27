package approvals

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/gatewaytest"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// testPartyID is the fixture party id (the signer's iss and the canned
// gatewaytest rows' party id) in every fixture below.
const testPartyID = "01HZYPARTY0000000000"

// fixture wires a fake gateway, a client signed by an Ed25519 key, and an
// approvals.Client bound to it; extra client options are appended last
// so a test can override the retry policy.
func fixture(t *testing.T, opts ...client.Option) (*gatewaytest.Gateway, *Client, ed25519.PrivateKey) {
	t.Helper()
	g := gatewaytest.NewGateway()
	t.Cleanup(g.Close)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	base := []client.Option{
		client.WithBaseURL(g.URL()),
		client.WithInsecureTransport(),
		client.WithSigner(testPartyID, priv),
	}
	cli, err := client.New(append(base, opts...)...)
	require.NoError(t, err)
	ap, err := New(cli)
	require.NoError(t, err)
	return g, ap, priv
}

// TestNewRejectsNilClient covers the constructor guard: a nil client
// fails New instead of deferring a nil panic to the first call.
func TestNewRejectsNilClient(t *testing.T) {
	ap, err := New(nil)
	require.Error(t, err)
	assert.Nil(t, ap)
}

// TestMintPostsWithPartyAuthAndIdempotencyKey covers assertion 1: Mint
// POSTs /v1/approvals with party auth and an Idempotency-Key and decodes
// the ticket response.
func TestMintPostsWithPartyAuthAndIdempotencyKey(t *testing.T) {
	g, ap, priv := fixture(t)
	resp, err := ap.Mint(context.Background(), wire.MintApprovalRequest{
		To: "01HZYPARTYRECIPIENT01", Scope: "referral",
		Purpose: "refer to cardiologist", TTL: 900,
	})
	require.NoError(t, err)
	assert.Equal(t, "eyJhbGciOiJFZERTQSIsImtpZCI6InFxLXBhcnR5LWtpZC0xIn0.cGF5bG9hZA.c2ln",
		resp.AccessToken, "mint must decode the ticket response")
	assert.Equal(t, "01HZYAPPROVALJTI000001", resp.JTI)
	assert.Equal(t, "2026-12-31T12:00:00Z", resp.ExpiresAt)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/v1/approvals", rec.Path)
	require.NotEmpty(t, rec.IdempotencyKey, "mint is an idempotent create (SDK-CLIENT-002)")
	require.True(t, strings.HasPrefix(rec.Authorization, "Bearer "), "mint must carry a party token")
	pub := priv.Public().(ed25519.PublicKey)
	_, _, err = jws.VerifyEd25519(pub, []byte(strings.TrimPrefix(rec.Authorization, "Bearer ")))
	require.NoError(t, err, "mint must be signed by the client signer")
	var body wire.MintApprovalRequest
	require.NoError(t, json.Unmarshal(rec.Body, &body))
	assert.Equal(t, "01HZYPARTYRECIPIENT01", body.To)
	assert.Equal(t, "referral", body.Scope)
	assert.Equal(t, "refer to cardiologist", body.Purpose)
}

// TestMintCapabilityDeniedSurfacesWireErrorAfterOneAttempt covers
// assertion 2: a 403 capability_denied returns *wire.Error after one
// attempt — a missing grant surfaces, it is never retried around.
func TestMintCapabilityDeniedSurfacesWireErrorAfterOneAttempt(t *testing.T) {
	g, ap, _ := fixture(t, client.WithRetry(client.RetryPolicy{
		MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond,
	}))
	g.Script(http.MethodPost, "/v1/approvals", gatewaytest.ScriptStep{
		Status: http.StatusForbidden,
		Body:   []byte(`{"error":{"code":"capability_denied","message":"party lacks the required capability","request_id":"req-sts-000"}}`),
	})
	_, err := ap.Mint(context.Background(), wire.MintApprovalRequest{
		To: "01HZYPARTYRECIPIENT01", Scope: "export:study-42",
		Purpose: "cohort extract", TTL: 900,
	})
	require.Error(t, err)
	var werr *wire.Error
	require.ErrorAs(t, err, &werr, "capability_denied must surface as *wire.Error")
	assert.Equal(t, wire.CodeCapabilityDenied, werr.Code)
	assert.Equal(t, http.StatusForbidden, werr.Status)
	assert.True(t, errors.Is(err, wire.ErrCapabilityDenied))
	assert.Len(t, g.Recorded(), 1, "capability_denied must cost exactly one attempt")
}
