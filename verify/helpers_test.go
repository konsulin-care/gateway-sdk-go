package verify_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/gatewaytest"
	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/verify"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// perKindSelf is the recipient identity (verifier "self") the minted-token
// tests use; every minted token's aud equals it.
const perKindSelf = "pty-test-recipient"

// goldenNow is the deterministic verification instant for the golden
// vectors: inside their [iat, exp] window (iat 1767225600, exp 1767226500),
// so the fixed clock never depends on wall-clock time.
var goldenNow = time.Unix(1_767_226_000, 0)

// perKindEnv is one offline fake gateway for the per-kind checks: an
// in-memory Ed25519 signing key, a loopback httptest JWKS endpoint serving
// its public half, and a Verifier with a deterministic clock. Nothing
// touches the network beyond the loopback listener.
type perKindEnv struct {
	priv ed25519.PrivateKey
	kid  string
	now  time.Time
	v    *verify.Verifier
}

// newPerKindEnv generates a fresh Ed25519 signing key, serves its JWKS on a
// local httptest endpoint, and builds a Verifier for the recipient self with
// a clock frozen at goldenNow. The server is closed via t.Cleanup.
//
// Parameters: t is the test; self is the recipient identity tokens must be
// addressed to (aud).
// Returns: a ready-to-use *perKindEnv whose v can Verify minted tokens.
func newPerKindEnv(t *testing.T, self string) *perKindEnv {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub, ok := priv.Public().(ed25519.PublicKey)
	require.True(t, ok, "ed25519 private key public half must be an ed25519.PublicKey")

	jwks, err := gatewaytest.Ed25519JWKS(pub)
	require.NoError(t, err)
	srv, err := gatewaytest.NewJWKSServer(jwks)
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	key := jwk.Key{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
	kid, err := key.Thumbprint()
	require.NoError(t, err)

	now := goldenNow
	v, err := verify.NewVerifier(srv.URL(), self,
		verify.WithClock(func() time.Time { return now }))
	require.NoError(t, err)
	return &perKindEnv{priv: priv, kid: kid, now: now, v: v}
}

// mint signs one compact token with the env's key over the raw JSON claims.
// A typ of "" omits the typ header member entirely (the missing-typ denial
// case); every other value is set verbatim.
//
// Parameters: t is the test; typ is the header typ (or "" to omit it);
// claims is the JSON claims object.
// Returns: the compact JWS.
func (e *perKindEnv) mint(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	tok, err := jws.SignEd25519(e.priv,
		jws.Header{Alg: jws.AlgEdDSA, Kid: e.kid, Typ: typ}, payload)
	require.NoError(t, err)
	return tok
}

// baseGatewayClaims returns the claim skeleton every gateway-signed kind
// carries: iss gateway, aud self, a sub, and a fresh iat/exp pair around
// the env's frozen clock.
func baseGatewayClaims(now time.Time, self string) map[string]any {
	return map[string]any{
		"iss": "gateway",
		"aud": self,
		"sub": "pty-test-sender",
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
}

// approvalClaims returns a well-formed ks-approval+jwt claims object.
func approvalClaims(now time.Time, self string) map[string]any {
	c := baseGatewayClaims(now, self)
	c["scope"] = "referral"
	c["purpose"] = "referral"
	c["researcher_hash"] = "N/A"
	c["jti"] = "jti-test-approval"
	return c
}

// accessClaims returns a well-formed ks-access+jwt claims object.
func accessClaims(now time.Time, self string) map[string]any {
	c := baseGatewayClaims(now, self)
	c["scope"] = "listing:lst-test"
	c["purpose"] = "payment:pay-test"
	c["jti"] = "jti-test-access"
	return c
}

// deliveryClaims returns a well-formed ks-delivery+jwt claims object whose
// body_sha256 covers body, without the conditional user_ref/payment_id.
func deliveryClaims(now time.Time, self, body string) map[string]any {
	c := baseGatewayClaims(now, self)
	c["purpose"] = wire.PurposeWebhookDelivery
	c["webhook_id"] = "wh-test-delivery"
	c["body_sha256"] = shaClaim([]byte(body))
	return c
}

// eventClaims returns a well-formed ks-event+jwt claims object for one of
// the four accepted purposes, with body_sha256 over body.
func eventClaims(now time.Time, self, body, purpose string) map[string]any {
	c := baseGatewayClaims(now, self)
	c["purpose"] = purpose
	c["webhook_id"] = "wh-test-event"
	c["body_sha256"] = shaClaim([]byte(body))
	return c
}

// resultClaims returns a well-formed ks-result+jwt claims object.
func resultClaims(now time.Time, self string) map[string]any {
	c := baseGatewayClaims(now, self)
	c["purpose"] = wire.PurposeWebhookResult
	c["jti"] = "jti-test-result"
	c["webhook_id"] = "wh-test-result"
	return c
}

// shaClaim renders the body_sha256 claim value over body: the base64url
// (unpadded) SHA-256 digest, exactly as the golden vectors carry it.
func shaClaim(body []byte) string {
	sum := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// cloneClaims returns a shallow copy of a claims map so a test case can
// mutate it without leaking into other cases.
func cloneClaims(c map[string]any) map[string]any {
	out := make(map[string]any, len(c))
	for k, v := range c {
		out[k] = v
	}
	return out
}

// newGoldenVerifier loads the mirrored golden vectors, serves the golden
// gateway JWKS on a local httptest endpoint, and builds a Verifier for the
// recipient self with the clock frozen inside the golden validity window.
//
// Parameters: t is the test; self is the recipient identity (one of the
// golden aud values).
// Returns: the Verifier and the fixtures keyed by file name.
func newGoldenVerifier(t *testing.T, self string) (*verify.Verifier, map[string]gatewaytest.Fixture) {
	t.Helper()
	fixtures, err := gatewaytest.LoadFixtures("../testdata/golden")
	require.NoError(t, err)
	srv, err := gatewaytest.NewJWKSServer(fixtures["gateway-jwks.json"].Data)
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	now := goldenNow
	v, err := verify.NewVerifier(srv.URL(), self,
		verify.WithClock(func() time.Time { return now }))
	require.NoError(t, err)
	return v, fixtures
}

// goldenJWT returns the compact token of one golden token vector.
func goldenJWT(t *testing.T, f gatewaytest.Fixture) string {
	t.Helper()
	var doc struct {
		JWT string `json:"jwt"`
	}
	require.NoError(t, json.Unmarshal(f.Data, &doc))
	require.NotEmpty(t, doc.JWT, "golden token vector must carry a jwt")
	return doc.JWT
}

// goldenBody returns the exact body bytes a golden delivery/event vector's
// body_sha256 covers, or nil when the vector carries no body member.
func goldenBody(t *testing.T, f gatewaytest.Fixture) []byte {
	t.Helper()
	var doc struct {
		Body *string `json:"body"`
	}
	require.NoError(t, json.Unmarshal(f.Data, &doc))
	if doc.Body == nil {
		return nil
	}
	return []byte(*doc.Body)
}
