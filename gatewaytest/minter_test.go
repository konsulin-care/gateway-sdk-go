package gatewaytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/konsulin-care/gateway-sdk-go/auth"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMinterMintsEdDSATokenAcceptedByFakeJWKS asserts that a token minted
// with the minter's generated Ed25519 test key verifies against the fake
// JWKS server through the EdDSA path: exact typ, alg EdDSA, kid = the RFC
// 7638 thumbprint of the minter key, and the payload round trip.
func TestMinterMintsEdDSATokenAcceptedByFakeJWKS(t *testing.T) {
	m, err := NewMinter()
	require.NoError(t, err)

	jwksData, err := m.JWKS()
	require.NoError(t, err)
	srv, err := NewJWKSServer(jwksData)
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	payload := []byte(`{"sub":"minter"}`)
	tok, err := m.Mint(wire.TypParty, payload)
	require.NoError(t, err)

	hdr, parsed, _, err := jws.Parse([]byte(tok))
	require.NoError(t, err)
	assert.Equal(t, wire.TypParty, hdr.Typ)
	assert.Equal(t, jws.AlgEdDSA, hdr.Alg)
	assert.Equal(t, m.Kid(), hdr.Kid)
	assert.Equal(t, ed25519Thumbprint(t, m.PublicKey()), hdr.Kid,
		"the kid must be the RFC 7638 thumbprint of the minter key")

	got, err := srv.Verify(tok)
	require.NoError(t, err, "a minted token must verify against the fake JWKS on the EdDSA path")
	assert.Equal(t, payload, got)
	assert.Equal(t, parsed, got)
}

// TestMinterES256RequiresExplicitOptIn asserts that ES256 minting is
// reachable only through the explicit opt-in key type: the default minter
// path has no algorithm input and always produces EdDSA for every typ, a
// zero-value opt-in key is rejected with no token, and only the explicit
// opt-in call yields an ES256 token — which every default EdDSA path then
// denies.
func TestMinterES256RequiresExplicitOptIn(t *testing.T) {
	m, err := NewMinter()
	require.NoError(t, err)
	jwksData, err := m.JWKS()
	require.NoError(t, err)
	srv, err := NewJWKSServer(jwksData)
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	payload := []byte(`{"sub":"minter"}`)

	// The default path never produces ES256 — for any of the six typs.
	for _, typ := range wire.Typs() {
		tok, err := m.Mint(typ, payload)
		require.NoError(t, err, "mint %s", typ)
		hdr, _, _, err := jws.Parse([]byte(tok))
		require.NoError(t, err)
		assert.Equal(t, jws.AlgEdDSA, hdr.Alg, "mint %s must be EdDSA", typ)
	}

	// Minting an ES256 token without the explicit opt-in is not possible:
	// the zero-value key is rejected and no token is returned.
	tok, err := MintES256(auth.ES256Key{}, payload)
	require.Error(t, err, "ES256 minting without the explicit opt-in must be impossible")
	assert.Contains(t, err.Error(), "opt-in")
	assert.Empty(t, tok)

	// The explicit opt-in produces an ES256 ks-party+jwt token.
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tok, err = MintES256(auth.ES256Key{Private: ecPriv}, payload)
	require.NoError(t, err)
	hdr, _, _, err := jws.Parse([]byte(tok))
	require.NoError(t, err)
	assert.Equal(t, wire.TypParty, hdr.Typ)
	assert.Equal(t, jws.AlgES256, hdr.Alg)

	// Every default EdDSA path denies it: the token-kind allow-list ...
	require.Error(t, jws.CheckKind(hdr, wire.TypParty))
	require.Error(t, jws.CheckKindParty(hdr, wire.TypParty, jws.PartyEdDSA))
	// ... the fake JWKS server (EdDSA-only, kid-only selection) ...
	_, err = srv.Verify(tok)
	require.Error(t, err, "the fake verify path must deny an ES256 token")
	// ... and a direct Ed25519 verify against the minter key.
	_, _, err = jws.VerifyEd25519(m.PublicKey(), []byte(tok))
	require.Error(t, err)

	// Only the explicit opt-in verification path accepts it.
	gotHdr, gotPayload, err := jws.VerifyES256(&ecPriv.PublicKey, []byte(tok))
	require.NoError(t, err)
	require.NoError(t, jws.CheckKindParty(gotHdr, wire.TypParty, jws.PartyES256))
	assert.Equal(t, payload, gotPayload)
}
