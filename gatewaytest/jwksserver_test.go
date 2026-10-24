package gatewaytest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ed25519Thumbprint returns the RFC 7638 thumbprint of an Ed25519 public key:
// the kid a token signed by that key must carry.
func ed25519Thumbprint(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	raw, err := json.Marshal(map[string]string{
		"crv": "Ed25519",
		"kty": "OKP",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	})
	require.NoError(t, err)
	kid, err := jwk.Thumbprint(raw)
	require.NoError(t, err)
	return kid
}

// TestFakeJWKSServerServesValidJWKS asserts that a GET on the served JWKS
// URL returns the exact served document and that its keys validate with the
// jwk package: every key parses and carries its RFC 7638 thumbprint as kid.
func TestFakeJWKSServerServesValidJWKS(t *testing.T) {
	fixtures, err := LoadFixtures(goldenDir)
	require.NoError(t, err)
	served := fixtures["gateway-jwks.json"].Data

	srv, err := NewJWKSServer(served)
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL())
	require.NoError(t, err, "the fake server is a local httptest listener")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(served, body),
		"GET must return the served JWKS byte-exact")

	keys, err := jwk.ParseJWKS(body)
	require.NoError(t, err, "served keys must validate with the jwk package")
	require.NotEmpty(t, keys.Keys)
	for _, key := range keys.Keys {
		kid, err := key.Thumbprint()
		require.NoError(t, err)
		assert.Equal(t, kid, key.Kid,
			"every served kid must be the key's RFC 7638 thumbprint")
	}
}

// TestFakeJWKSServerRejectsInvalidJWKS asserts that a malformed document
// fails closed at construction with no server started.
func TestFakeJWKSServerRejectsInvalidJWKS(t *testing.T) {
	srv, err := NewJWKSServer([]byte(`{"keys":"nope"}`))
	require.Error(t, err, "a malformed JWKS must fail at construction")
	assert.Nil(t, srv, "no server must be returned on error")
}

// TestFakeJWKSServerKidOnlyVerify asserts that the fake verify path selects
// the key by the token's own kid only: a token signed by the served key is
// accepted and yields its payload, a token signed with an unknown kid is
// denied before any signature check, and a served kid carrying a foreign
// signature is denied by the Ed25519 verification.
func TestFakeJWKSServerKidOnlyVerify(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwksData, err := Ed25519JWKS(pubA)
	require.NoError(t, err)
	srv, err := NewJWKSServer(jwksData)
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	keys, err := jwk.ParseJWKS(jwksData)
	require.NoError(t, err)
	require.Len(t, keys.Keys, 1)
	kidA := ed25519Thumbprint(t, pubA)
	kidB := ed25519Thumbprint(t, pubB)
	assert.Equal(t, kidA, keys.Keys[0].Kid,
		"the served kid must be the RFC 7638 thumbprint of the served key")
	assert.NotEqual(t, kidA, kidB, "distinct keys have distinct thumbprints")

	payload := []byte(`{"sub":"gateway-verify-path"}`)
	good, err := jws.SignEd25519(privA,
		jws.Header{Alg: jws.AlgEdDSA, Kid: kidA, Typ: "ks-party+jwt"}, payload)
	require.NoError(t, err)
	got, err := srv.Verify(good)
	require.NoError(t, err, "a token signed by the served key must verify")
	assert.Equal(t, payload, got, "Verify must return the verified payload")

	unknown, err := jws.SignEd25519(privB,
		jws.Header{Alg: jws.AlgEdDSA, Kid: kidB, Typ: "ks-party+jwt"}, payload)
	require.NoError(t, err)
	_, err = srv.Verify(unknown)
	require.Error(t, err, "a token signed with an unknown kid must be denied")
	assert.Contains(t, err.Error(), "unknown kid")

	forged, err := jws.SignEd25519(privB,
		jws.Header{Alg: jws.AlgEdDSA, Kid: kidA, Typ: "ks-party+jwt"}, payload)
	require.NoError(t, err)
	_, err = srv.Verify(forged)
	require.Error(t, err, "a served kid with a foreign signature must be denied")
	assert.Contains(t, err.Error(), "signature")
}
