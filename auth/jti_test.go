package auth_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/auth"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// attemptJti parses a compact ks-party+jwt token and returns its jti claim.
func attemptJti(t *testing.T, tok string) string {
	t.Helper()
	_, payload, _, err := jws.Parse([]byte(tok))
	require.NoError(t, err)
	var claims auth.PartyClaims
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims.Jti
}

// TestSignPartyAttemptFreshJtiPerAttempt asserts SDK-AUTH-003: signing the
// same claims twice yields two distinct jti values and two distinct tokens,
// and every retry of one logical request mints a jti no earlier attempt has
// used. Both attempt tokens stay valid on the standard verification path.
func TestSignPartyAttemptFreshJtiPerAttempt(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	base := partyClaims("caller-supplied-jti") // one logical request

	first, err := auth.SignPartyAttempt(priv, base)
	require.NoError(t, err)
	retry, err := auth.SignPartyAttempt(priv, base)
	require.NoError(t, err)

	jtiFirst := attemptJti(t, first)
	jtiRetry := attemptJti(t, retry)
	require.NotEqual(t, jtiFirst, jtiRetry)
	assert.NotEqual(t, first, retry)
	assert.Equal(t, "caller-supplied-jti", base.Jti) // input claims untouched

	// Retries never replay: each further attempt of the same logical
	// request mints a fresh jti — the gateway's replay store rejects a
	// second presentation of the same one.
	seen := map[string]bool{jtiFirst: true, jtiRetry: true}
	for i := 0; i < 8; i++ {
		tok, err := auth.SignPartyAttempt(priv, base)
		require.NoError(t, err)
		jti := attemptJti(t, tok)
		require.False(t, seen[jti], "attempt %d replayed jti %q", i, jti)
		seen[jti] = true
	}

	// Both the first attempt and the retry verify on the standard path.
	for _, tok := range []string{first, retry} {
		hdr, _, err := jws.VerifyEd25519(pub, []byte(tok))
		require.NoError(t, err)
		require.NoError(t, jws.CheckKindParty(hdr, wire.TypParty, jws.PartyEdDSA))
	}

	// Why minting matters: Ed25519 signing is deterministic, so the same
	// claims on the static-jti path produce byte-identical tokens — a fresh
	// jti is what distinguishes two attempts of one logical request.
	static1, err := auth.SignPartyRequest(priv, base)
	require.NoError(t, err)
	static2, err := auth.SignPartyRequest(priv, base)
	require.NoError(t, err)
	assert.Equal(t, static1, static2)
}

// TestSignPartyAttemptES256FreshJti asserts the explicit opt-in ES256 path
// also mints a fresh jti per attempt: no signing path can replay a jti.
func TestSignPartyAttemptES256FreshJti(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	base := partyClaims("caller-supplied-jti-es")

	first, err := auth.SignPartyAttemptES256(auth.ES256Key{Private: ecPriv}, base)
	require.NoError(t, err)
	retry, err := auth.SignPartyAttemptES256(auth.ES256Key{Private: ecPriv}, base)
	require.NoError(t, err)

	assert.NotEqual(t, attemptJti(t, first), attemptJti(t, retry))
	assert.Equal(t, "caller-supplied-jti-es", base.Jti)
}

// TestNewJtiFreshAndUnpadded asserts each minted jti is valid unpadded
// base64url and unique across calls — no clock or counter state.
func TestNewJtiFreshAndUnpadded(t *testing.T) {
	seen := make(map[string]bool, 32)
	for i := 0; i < 32; i++ {
		jti, err := auth.NewJti()
		require.NoError(t, err)
		require.NotEmpty(t, jti)
		assert.NotContains(t, jti, "=")
		_, err = base64.RawURLEncoding.DecodeString(jti)
		require.NoError(t, err, "jti %q must be unpadded base64url", jti)
		require.False(t, seen[jti], "jti %q replayed", jti)
		seen[jti] = true
	}
}
