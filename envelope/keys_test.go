package envelope

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// alicePrivStdB64 is RFC 7748 section 6.1 Alice's static private scalar
// (rfc7748AlicePriv, pinned by TestX25519SharedSecretRFC7748Vector)
// rendered in the std base64 encoding the gateway's genkey output uses.
const alicePrivStdB64 = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="

// TestParseX25519PrivateKeyGoldenVector asserts a fixed std-base64 key
// (SDKP-006) decodes to the RFC 7748 section 6.1 Alice scalar and derives
// her published public key bytes — the pinned genkey-format golden vector.
func TestParseX25519PrivateKeyGoldenVector(t *testing.T) {
	wantPriv, err := hex.DecodeString(rfc7748AlicePriv)
	require.NoError(t, err)
	decoded, err := base64.StdEncoding.DecodeString(alicePrivStdB64)
	require.NoError(t, err)
	require.Equal(t, wantPriv, decoded,
		"the pinned std-base64 constant must decode to the RFC 7748 Alice scalar")

	priv, err := ParseX25519PrivateKey(alicePrivStdB64)
	require.NoError(t, err)
	wantPub, err := hex.DecodeString(rfc7748AlicePub)
	require.NoError(t, err)
	assert.Equal(t, wantPub, priv.PublicKey().Bytes(),
		"the parsed key must derive the RFC 7748 Alice public key")
}

// TestEncJWKThumbprintAndSelect asserts EncJWK produces an OKP/X25519
// use:enc wire.JWK whose x is the public coordinate and whose kid is the
// RFC 7638 thumbprint computed independently here, and that SelectEncKey
// discovers the key by exactly that kid.
func TestEncJWKThumbprintAndSelect(t *testing.T) {
	priv, err := ParseX25519PrivateKey(alicePrivStdB64)
	require.NoError(t, err)
	pub := priv.PublicKey()

	encKey, err := EncJWK(pub)
	require.NoError(t, err)
	assert.Equal(t, "OKP", encKey.Kty, "kty must be OKP")
	assert.Equal(t, "X25519", encKey.Crv, "crv must be X25519")
	assert.Equal(t, "enc", encKey.Use, "use must be enc")
	x := base64.RawURLEncoding.EncodeToString(pub.Bytes())
	assert.Equal(t, x, encKey.X, "x must be the base64url public coordinate")

	// Independent RFC 7638 thumbprint: canonical JSON of the OKP required
	// members crv, kty, x (lexicographic, no whitespace), SHA-256, base64url.
	sum := sha256.Sum256(
		[]byte(`{"crv":"X25519","kty":"OKP","x":"` + x + `"}`))
	wantKid := base64.RawURLEncoding.EncodeToString(sum[:])
	assert.Equal(t, wantKid, encKey.Kid, "kid must be the RFC 7638 thumbprint")

	raw, err := json.Marshal(wire.JWKSResponse{Keys: []wire.JWK{encKey}})
	require.NoError(t, err)
	got, err := SelectEncKey(raw, encKey.Kid)
	require.NoError(t, err)
	assert.True(t, got.Equal(pub),
		"SelectEncKey must discover the published key by its thumbprint kid")
}

// TestParseX25519PrivateKeyErrorsOmitInput asserts malformed base64 and
// wrong-length inputs fail closed with errors that never echo the input
// string or any key material.
func TestParseX25519PrivateKeyErrorsOmitInput(t *testing.T) {
	full, err := base64.StdEncoding.DecodeString(alicePrivStdB64)
	require.NoError(t, err)

	cases := []struct {
		name string
		in   string
	}{
		{"malformed base64", "@@@not-base64@@@"},
		{"truncated 31 bytes", base64.StdEncoding.EncodeToString(full[:31])},
		{"overlong 33 bytes",
			base64.StdEncoding.EncodeToString(append(append([]byte{}, full...), 0x00))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ParseX25519PrivateKey(tc.in)
			require.Error(t, err)
			assert.Nil(t, key)
			assert.NotContains(t, err.Error(), tc.in)
		})
	}
}
