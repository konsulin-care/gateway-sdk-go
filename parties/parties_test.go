package parties

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/auth"
	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/gatewaytest"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// testPartyID is the canned parties route's party id (gatewaytest
// EnrollPartyResponse.PartyID) and the signer's party id in every fixture.
const testPartyID = "01HZYPARTY0000000000"

// testClaims returns structurally valid ks-party+jwt claims for the
// fixture party (SDK-AUTH-001: aud gateway, exp <= iat+300); the jti is a
// placeholder — the SDK mints a fresh one per attempt.
func testClaims() auth.PartyClaims {
	now := time.Now().Unix()
	return auth.PartyClaims{
		Aud: "gateway", Iss: testPartyID,
		Iat: now, Exp: now + auth.MaxPartyLifetime, Jti: "fixture-placeholder-jti",
	}
}

// fixture wires a fake gateway, a client signed by an Ed25519 key, and a
// parties.Client bound to both; extra client options are appended last so
// a test can override the retry policy.
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
	p, err := New(cli, g.URL())
	require.NoError(t, err)
	return g, p, priv
}

// TestEnrollSendsProofBodyAndIdempotencyKey covers assertion 1: Enroll
// POSTs /v1/parties/{id}/enroll with the BuildEnrollment body bytes, a
// Bearer proof, and an Idempotency-Key.
func TestEnrollSendsProofBodyAndIdempotencyKey(t *testing.T) {
	g, p, priv := fixture(t)
	resp, err := p.Enroll(context.Background(), EnrollInput{
		PartyID: testPartyID, EnrollmentToken: "enroll-token-001",
	}, priv)
	require.NoError(t, err)
	assert.Equal(t, testPartyID, resp.PartyID)
	assert.Equal(t, "qc-party-kid-1", resp.Kid)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/v1/parties/"+testPartyID+"/enroll", rec.Path)
	require.NotEmpty(t, rec.IdempotencyKey)
	require.True(t, strings.HasPrefix(rec.Authorization, "Bearer "), "enroll must carry a Bearer proof")
	hdr, payload, _, err := jws.Parse([]byte(strings.TrimPrefix(rec.Authorization, "Bearer ")))
	require.NoError(t, err)
	assert.Equal(t, jws.AlgEdDSA, hdr.Alg)
	assert.Contains(t, string(payload), "body_sha256")

	want, err := auth.BuildEnrollment(auth.EnrollmentInput{
		Claims: testClaims(), EnrollmentToken: "enroll-token-001",
	}, priv)
	require.NoError(t, err)
	assert.Equal(t, want.Body, rec.Body, "enroll body must equal the BuildEnrollment bytes")
}

// TestEnrollRetryAfter503KeepsBodyAndKeyChangesJti covers assertion 2:
// an Enroll retried after 503 sends identical body bytes, the same
// Idempotency-Key, and a proof with a different jti.
func TestEnrollRetryAfter503KeepsBodyAndKeyChangesJti(t *testing.T) {
	g, p, priv := fixture(t)
	g.Script(http.MethodPost, "/v1/parties/{id}/enroll",
		gatewaytest.ScriptStep{Status: http.StatusServiceUnavailable})
	resp, err := p.Enroll(context.Background(), EnrollInput{
		PartyID: testPartyID, EnrollmentToken: "enroll-token-retry",
	}, priv)
	require.NoError(t, err)
	assert.Equal(t, "qc-party-kid-1", resp.Kid)

	recs := g.Recorded()
	require.Len(t, recs, 2, "one retryable 503 must cost exactly one retry")
	assert.Equal(t, recs[0].Body, recs[1].Body, "retried enroll must send identical body bytes")
	require.NotEmpty(t, recs[0].IdempotencyKey)
	assert.Equal(t, recs[0].IdempotencyKey, recs[1].IdempotencyKey, "retry must reuse the call's Idempotency-Key")
	require.NotEmpty(t, recs[0].PartyJTI)
	require.NotEmpty(t, recs[1].PartyJTI)
	assert.NotEqual(t, recs[0].PartyJTI, recs[1].PartyJTI, "each attempt must carry a fresh jti (SDK-AUTH-003)")
}

// TestEnrollES256SendsES256BodyAndProofHeader covers assertion 3:
// EnrollES256 sends body alg ES256 and an ES256 proof header.
func TestEnrollES256SendsES256BodyAndProofHeader(t *testing.T) {
	g, p, _ := fixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	resp, err := p.EnrollES256(context.Background(), EnrollInput{
		PartyID: testPartyID, EnrollmentToken: "enroll-token-es256",
	}, auth.ES256Key{Private: key})
	require.NoError(t, err)
	assert.Equal(t, "qc-party-kid-1", resp.Kid)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	var body map[string]any
	require.NoError(t, json.Unmarshal(recs[0].Body, &body))
	assert.Equal(t, "ES256", body["alg"], "es256 enroll body must carry alg ES256")
	hdr, _, _, err := jws.Parse([]byte(strings.TrimPrefix(recs[0].Authorization, "Bearer ")))
	require.NoError(t, err)
	assert.Equal(t, jws.AlgES256, hdr.Alg, "es256 enroll proof must carry an ES256 header")
}

// TestRotateSignsWithPartyTokenAndDecodesKid covers assertion 4: Rotate
// POSTs /v1/parties/{id}/keys signed by the client signer with an
// Idempotency-Key and decodes {kid}.
func TestRotateSignsWithPartyTokenAndDecodesKid(t *testing.T) {
	g, p, priv := fixture(t)
	resp, err := p.Rotate(context.Background(), testPartyID, wire.RotateKeyRequest{
		PublicKey: "cHVibGljLWtleS1ieXRlcy1wdWJsaWM=", Kid: "qc-party-kid-2",
	})
	require.NoError(t, err)
	assert.Equal(t, "qc-party-kid-2", resp.Kid)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/v1/parties/"+testPartyID+"/keys", rec.Path)
	require.NotEmpty(t, rec.IdempotencyKey, "rotate is an idempotent create (SDK-CLIENT-002)")
	token := strings.TrimPrefix(rec.Authorization, "Bearer ")
	pub := priv.Public().(ed25519.PublicKey)
	_, _, err = jws.VerifyEd25519(pub, []byte(token))
	require.NoError(t, err, "rotate must be signed by the client signer")
}

// TestRotateForbiddenParty011ReturnsWireErrorAfterOneAttempt covers
// assertion 5: Rotate answered 403 GW-PARTY-011 returns *wire.Error after
// one attempt even under a retrying policy (SDK-RETRY-003: fix-request
// codes are terminal).
func TestRotateForbiddenParty011ReturnsWireErrorAfterOneAttempt(t *testing.T) {
	g, p, _ := fixture(t, client.WithRetry(client.RetryPolicy{
		MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond,
	}))
	g.Script(http.MethodPost, "/v1/parties/{id}/keys", gatewaytest.ScriptStep{
		Status: http.StatusForbidden,
		Body:   []byte(`{"error":{"code":"GW-PARTY-011","message":"superseded key","request_id":"req-party-011"}}`),
	})
	_, err := p.Rotate(context.Background(), testPartyID, wire.RotateKeyRequest{
		PublicKey: "cHVibGljLWtleS1ieXRlcy1wdWJsaWM=", Kid: "qc-party-kid-3",
	})
	var gwErr *wire.Error
	require.ErrorAs(t, err, &gwErr)
	assert.Equal(t, "GW-PARTY-011", gwErr.Code)
	assert.Equal(t, http.StatusForbidden, gwErr.Status)
	assert.Len(t, g.Recorded(), 1, "403 GW-PARTY-011 must cost exactly one attempt")
}

// TestJWKSGetsWithoutAuthorization covers assertion 6: JWKS GETs
// /v1/parties/{id}/jwks without Authorization and decodes the key set.
func TestJWKSGetsWithoutAuthorization(t *testing.T) {
	g, p, _ := fixture(t)
	resp, err := p.JWKS(context.Background(), testPartyID)
	require.NoError(t, err)
	require.Len(t, resp.Keys, 1)
	assert.Equal(t, "qc-party-kid-1", resp.Keys[0].Kid)
	assert.Equal(t, "OKP", resp.Keys[0].Kty)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	assert.Equal(t, http.MethodGet, recs[0].Method)
	assert.Equal(t, "/v1/parties/"+testPartyID+"/jwks", recs[0].Path)
	assert.Empty(t, recs[0].Authorization, "jwks is a public route: no Authorization header")
}

// TestHealthSendsPartyToken covers assertion 7: Health GETs
// /v1/parties/{id}/health with a party token.
func TestHealthSendsPartyToken(t *testing.T) {
	g, p, _ := fixture(t)
	resp, err := p.Health(context.Background(), testPartyID)
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.Status)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	assert.Equal(t, http.MethodGet, recs[0].Method)
	assert.Equal(t, "/v1/parties/"+testPartyID+"/health", recs[0].Path)
	assert.True(t, strings.HasPrefix(recs[0].Authorization, "Bearer "), "health must carry a party token")
}
