package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/gatewaytest"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// testPartyID is the fixture party id of the client's signer below: a
// signer is configured on purpose so the "no Authorization" assertions
// prove the public routes never sign, even when they could.
const testPartyID = "01HZYPARTY0000000000"

// fixture wires a fake gateway and a gateway routes Client bound to a
// client configured with a party signer; extra client options are
// appended last so a test can override the retry policy.
func fixture(t *testing.T, opts ...client.Option) (*gatewaytest.Gateway, *Client) {
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
	gw, err := New(cli)
	require.NoError(t, err)
	return g, gw
}

// TestJWKSGetsWellKnownWithoutAuthorization covers assertion 1: JWKS
// GETs /.well-known/jwks with the route's public auth class — no
// Authorization header even though the client holds a signer — and
// returns the served key set.
func TestJWKSGetsWellKnownWithoutAuthorization(t *testing.T) {
	g, gw := fixture(t)
	resp, err := gw.JWKS(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Keys, 1, "jwks must return the served key set")
	key := resp.Keys[0]
	assert.Equal(t, "OKP", key.Kty)
	assert.Equal(t, "Ed25519", key.Crv)
	assert.Equal(t, "qc-party-kid-1", key.Kid)
	assert.Equal(t, "cGFydHkta2V5LXg0My1jaGFyYmFzZTY0dXJs", key.X)
	assert.Equal(t, "EdDSA", key.Alg)
	assert.Equal(t, "sig", key.Use)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodGet, rec.Method)
	assert.Equal(t, "/.well-known/jwks", rec.Path)
	assert.Empty(t, rec.Authorization, "the public JWKS read must send no Authorization header")
	assert.Empty(t, rec.IdempotencyKey, "a read must not send an Idempotency-Key")
	assert.Empty(t, rec.Body, "the JWKS read carries no request body")
}

// TestHealthGetsWithoutAuthorizationAndDecodesStatus covers assertion
// 2: Health GETs /health with the route's public auth class — no
// Authorization header — and decodes the status body.
func TestHealthGetsWithoutAuthorizationAndDecodesStatus(t *testing.T) {
	g, gw := fixture(t)
	resp, err := gw.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Status, "health must decode the status body")
	assert.Equal(t, "1.4.2", resp.Version)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodGet, rec.Method)
	assert.Equal(t, "/health", rec.Path)
	assert.Empty(t, rec.Authorization, "the public health read must send no Authorization header")
	assert.Empty(t, rec.IdempotencyKey, "a read must not send an Idempotency-Key")
}

// TestNon2xxReturnsWireError covers assertion 3: a non-2xx answer on
// either public route surfaces as *wire.Error (SDK-CLIENT-003) with the
// envelope's code and the response status — never a decoded body and
// never a plain error.
func TestNon2xxReturnsWireError(t *testing.T) {
	cases := []struct {
		name string
		verb string
		path string
		call func(context.Context, *Client) error
	}{
		{"jwks", http.MethodGet, "/.well-known/jwks", func(ctx context.Context, gw *Client) error {
			_, err := gw.JWKS(ctx)
			return err
		}},
		{"health", http.MethodGet, "/health", func(ctx context.Context, gw *Client) error {
			_, err := gw.Health(ctx)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, gw := fixture(t)
			g.Script(tc.verb, tc.path, gatewaytest.ScriptStep{
				Status: http.StatusNotFound,
				Body:   []byte(`{"error":{"code":"GW-PARTY-001","message":"not found","request_id":"req-gw-404"}}`),
			})
			err := tc.call(context.Background(), gw)
			var gwErr *wire.Error
			require.ErrorAs(t, err, &gwErr, "a non-2xx must surface as *wire.Error")
			assert.Equal(t, http.StatusNotFound, gwErr.Status)
			assert.Equal(t, "GW-PARTY-001", gwErr.Code)
			assert.Equal(t, "req-gw-404", gwErr.RequestID)
		})
	}
}
