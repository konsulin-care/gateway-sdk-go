package auth_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/auth"
	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// partyClaims returns valid ks-party+jwt claims at the inclusive lifetime
// boundary exp = iat + MaxPartyLifetime.
func partyClaims(jti string) auth.PartyClaims {
	const iat = int64(1700000000)
	return auth.PartyClaims{
		Aud: "gateway",
		Exp: iat + auth.MaxPartyLifetime,
		Iat: iat,
		Iss: "pty-test",
		Jti: jti,
	}
}

// ed25519KID returns the RFC 7638 thumbprint of an Ed25519 public key, the
// header kid every EdDSA party token must carry.
func ed25519KID(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	key, err := jwk.ParseKey([]byte(`{"kty":"OKP","crv":"Ed25519","x":"` +
		base64.RawURLEncoding.EncodeToString(pub) + `"}`))
	require.NoError(t, err)
	kid, err := key.Thumbprint()
	require.NoError(t, err)
	return kid
}

// p256KID returns the RFC 7638 thumbprint of a P-256 public key, the header
// kid every ES256 party token must carry.
func p256KID(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	b, err := pub.Bytes()
	require.NoError(t, err)
	require.Len(t, b, 65)
	key, err := jwk.ParseKey([]byte(fmt.Sprintf(
		`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`,
		base64.RawURLEncoding.EncodeToString(b[1:33]),
		base64.RawURLEncoding.EncodeToString(b[33:65]),
	)))
	require.NoError(t, err)
	kid, err := key.Thumbprint()
	require.NoError(t, err)
	return kid
}

// TestSignPartyRequestEdDSADefault asserts the default signing path
// (SDK-AUTH-001) produces a ks-party+jwt token with header typ ks-party+jwt,
// alg EdDSA, kid = RFC 7638 thumbprint of the signing key, exp no later than
// iat+300, and a payload in the exact byte order the golden vectors pin.
func TestSignPartyRequestEdDSADefault(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	claims := partyClaims("jti-1")

	tok, err := auth.SignPartyRequest(priv, claims)
	require.NoError(t, err)

	hdr, payload, _, err := jws.Parse([]byte(tok))
	require.NoError(t, err)
	assert.Equal(t, wire.TypParty, hdr.Typ)
	assert.Equal(t, jws.AlgEdDSA, hdr.Alg)
	assert.NotEqual(t, jws.AlgES256, hdr.Alg)
	assert.Equal(t, ed25519KID(t, pub), hdr.Kid)
	assert.LessOrEqual(t, claims.Exp, claims.Iat+auth.MaxPartyLifetime)

	// Byte-exact claim order (aud, exp, iat, iss, jti) — the SDK-AUTH-C01
	// golden reproduction depends on this serialization.
	assert.Equal(t,
		`{"aud":"gateway","exp":1700000300,"iat":1700000000,"iss":"pty-test","jti":"jti-1"}`,
		string(payload))

	// The same verification path the caller applies accepts the token.
	gotHdr, gotPayload, err := jws.VerifyEd25519(pub, []byte(tok))
	require.NoError(t, err)
	require.NoError(t, jws.CheckKindParty(gotHdr, wire.TypParty, jws.PartyEdDSA))
	assert.Equal(t, payload, gotPayload)
}

// TestSignPartyRequestRejectsExpiryBeyondMax asserts a request for exp beyond
// iat+300 is rejected, exp == iat is rejected, and the boundary iat+300 is
// accepted (the bound is inclusive).
func TestSignPartyRequestRejectsExpiryBeyondMax(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	beyond := partyClaims("jti-2")
	beyond.Exp = beyond.Iat + auth.MaxPartyLifetime + 1
	_, err = auth.SignPartyRequest(priv, beyond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "300")

	expired := partyClaims("jti-3")
	expired.Exp = expired.Iat
	_, err = auth.SignPartyRequest(priv, expired)
	require.Error(t, err)

	boundary := partyClaims("jti-4") // exp == iat + MaxPartyLifetime
	_, err = auth.SignPartyRequest(priv, boundary)
	require.NoError(t, err)
}

// TestSignPartyRequestRequiresClaims asserts the SDK-AUTH-001 required claims
// (iss, aud, jti) are enforced before signing.
func TestSignPartyRequestRequiresClaims(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for _, mutate := range []func(*auth.PartyClaims){
		func(c *auth.PartyClaims) { c.Iss = "" },
		func(c *auth.PartyClaims) { c.Aud = "" },
		func(c *auth.PartyClaims) { c.Jti = "" },
	} {
		claims := partyClaims("jti-5")
		mutate(&claims)
		_, err := auth.SignPartyRequest(priv, claims)
		require.Error(t, err, "claims %+v must be rejected", claims)
	}
}

// TestSignPartyRequestES256RequiresOptIn asserts ES256 party signing is
// reachable only through the explicit opt-in key type: an ECDSA key through
// the default path is rejected, and the default allow-list denies the
// resulting ES256 token.
func TestSignPartyRequestES256RequiresOptIn(t *testing.T) {
	claims := partyClaims("jti-es")
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// An ECDSA key through the default path is rejected, not silently
	// upgraded to ES256.
	_, err = auth.SignPartyRequest(ecPriv, claims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "opt-in")

	// A nil opt-in key is rejected.
	_, err = auth.SignPartyRequestES256(auth.ES256Key{}, claims)
	require.Error(t, err)

	// The explicit opt-in path produces an ES256 ks-party+jwt token.
	tok, err := auth.SignPartyRequestES256(auth.ES256Key{Private: ecPriv}, claims)
	require.NoError(t, err)

	hdr, payload, _, err := jws.Parse([]byte(tok))
	require.NoError(t, err)
	assert.Equal(t, wire.TypParty, hdr.Typ)
	assert.Equal(t, jws.AlgES256, hdr.Alg)
	assert.Equal(t, p256KID(t, &ecPriv.PublicKey), hdr.Kid)

	// ES256 stays outside every default path: the default allow-list for
	// ks-party+jwt is EdDSA-only.
	require.Error(t, jws.CheckKind(hdr, wire.TypParty))
	require.Error(t, jws.CheckKindParty(hdr, wire.TypParty, jws.PartyEdDSA))

	// The opt-in verification path accepts the token.
	gotHdr, gotPayload, err := jws.VerifyES256(&ecPriv.PublicKey, []byte(tok))
	require.NoError(t, err)
	require.NoError(t, jws.CheckKindParty(gotHdr, wire.TypParty, jws.PartyES256))
	assert.Equal(t, payload, gotPayload)
}
