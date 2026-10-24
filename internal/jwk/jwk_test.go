package jwk_test

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
)

// rfc7638Section31JWK is the example JWK of RFC 7638 section 3.1 (an RSA key).
// The published thumbprint of this key is defined in the same section; the
// extra "kid" member proves that members beyond the required set do not
// influence the thumbprint.
const rfc7638Section31JWK = `{
	"kty": "RSA",
	"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	"e": "AQAB",
	"kid": "2011-04-29"
}`

// rfc7515AppendixA1JWK is the EC P-256 JWK of RFC 7515 Appendix A.1, used as
// the EC thumbprint vector (RFC 7638 section 3.2 canonical form).
const rfc7515AppendixA1JWK = `{
	"kty": "EC",
	"crv": "P-256",
	"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
	"y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	"kid": "74c0d034-c1b1-44f8-8df2-8f1c4b19b1e8"
}`

// x25519X is a fixed OKP/X25519 public coordinate (base64url, unpadded, 32
// bytes) used as the use:enc key fixture in these tests.
const x25519X = "3hy4vB5JnwFj4w2MHRvYKN-n6I8OFs7EVUrqF73tRk0"

// x25519EncJWK is a valid encryption key fixture: use "enc" and alg "ECDH-ES"
// exactly as the JWE Envelope contract requires of an X25519 recipient key.
const x25519EncJWK = `{"alg":"ECDH-ES","crv":"X25519","kid":"enc-current","kty":"OKP","use":"enc","x":"` + x25519X + `"}`

// ed25519SigJWK is a signing key fixture carrying the coordinate of the
// mirrored gateway JWKS, reused as the sig half of the mixed sets below.
const ed25519SigJWK = `{"alg":"EdDSA","crv":"Ed25519","kid":"sig-current","kty":"OKP","use":"sig","x":"iRjI0Qr9WRzkvTcY4bv8tAGPgBGrj83PSikHxaRFKyM"}`

// TestRFC7638Section31Vector asserts the thumbprint of the RFC 7638 section 3.1
// example JWK equals the published value verbatim.
func TestRFC7638Section31Vector(t *testing.T) {
	got, err := jwk.Thumbprint([]byte(rfc7638Section31JWK))
	require.NoError(t, err)
	assert.Equal(t, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", got)
}

// TestThumbprintECP256 asserts the RFC 7638 thumbprint of the RFC 7515
// Appendix A.1 EC P-256 key. Per RFC 7638 section 3.2 the EC canonical form
// is crv/kty/x only; the y coordinate and any other member never contribute.
func TestThumbprintECP256(t *testing.T) {
	got, err := jwk.Thumbprint([]byte(rfc7515AppendixA1JWK))
	require.NoError(t, err)
	assert.Equal(t, "sxXPnpAh91l74LBB0I9ivWUQF31L6hri_vWWA50i0Yo", got)
}

// TestThumbprintX25519OverCRVKTYX asserts the RFC 7638 thumbprint of an
// X25519 key is the SHA-256 of the canonical crv/kty/x form and nothing
// else: use, alg, and kid never contribute to the digest.
func TestThumbprintX25519OverCRVKTYX(t *testing.T) {
	canonical := `{"crv":"X25519","kty":"OKP","x":"` + x25519X + `"}`
	sum := sha256.Sum256([]byte(canonical))
	want := base64.RawURLEncoding.EncodeToString(sum[:])

	key, err := jwk.ParseKey([]byte(x25519EncJWK))
	require.NoError(t, err)
	got, err := key.Thumbprint()
	require.NoError(t, err)
	assert.Equal(t, want, got, "thumbprint must hash crv/kty/x only")

	bare, err := jwk.Thumbprint([]byte(canonical))
	require.NoError(t, err)
	assert.Equal(t, want, bare)
}

// TestThumbprintRejectsMalformed asserts unsupported or incomplete JWKs fail
// the thumbprint computation instead of producing a digest.
func TestThumbprintRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"not json":       `{"kty":`,
		"not an object":  `["OKP"]`,
		"missing kty":    `{"crv":"Ed25519","x":"abc"}`,
		"kty not string": `{"kty":7}`,
		"unknown kty":    `{"kty":"DH"}`,
		"missing crv":    `{"kty":"OKP","x":"abc"}`,
		"missing x":      `{"kty":"OKP","crv":"Ed25519"}`,
		"x not string":   `{"kty":"OKP","crv":"Ed25519","x":1}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := jwk.Thumbprint([]byte(in))
			assert.Error(t, err)
		})
	}
}

// TestParseGatewayJWKS asserts the mirrored golden gateway-jwks.json parses to
// exactly one Ed25519 key whose kid equals the RFC 7638 thumbprint of that key.
func TestParseGatewayJWKS(t *testing.T) {
	data, err := os.ReadFile("../../testdata/golden/gateway-jwks.json")
	require.NoError(t, err)

	set, err := jwk.ParseJWKS(data)
	require.NoError(t, err)
	require.Len(t, set.Keys, 1)

	key := set.Keys[0]
	assert.Equal(t, "OKP", key.Kty)
	assert.Equal(t, "Ed25519", key.Crv)
	assert.Equal(t, "EdDSA", key.Alg)
	assert.Equal(t, "sig", key.Use)
	assert.Equal(t, "iRjI0Qr9WRzkvTcY4bv8tAGPgBGrj83PSikHxaRFKyM", key.X)

	thumbprint, err := key.Thumbprint()
	require.NoError(t, err)
	assert.Equal(t, "UKdQhmfoDfmQoA5U3p6EACeE-5iHXUt6y4nf28IWRmU", key.Kid)
	assert.Equal(t, key.Kid, thumbprint)

	// Kid-only selection resolves the served signing key; the set holds no
	// encryption key, so EncByKid resolves nothing at all.
	selected, ok := set.SigByKid(key.Kid)
	require.True(t, ok)
	assert.Equal(t, key, selected)
	_, ok = set.SigByKid("unknown-kid")
	assert.False(t, ok)
	_, ok = set.SigByKid("")
	assert.False(t, ok)
	_, ok = set.EncByKid(key.Kid)
	assert.False(t, ok, "an Ed25519 sig key must never resolve through EncByKid")
	_, ok = set.EncByKid("")
	assert.False(t, ok)
}

// TestParseJWKSHoldsCurrentAndPrevious asserts a rotation-overlap JWKS retains
// both the current and the previous signing key and selects each by kid.
func TestParseJWKSHoldsCurrentAndPrevious(t *testing.T) {
	const doc = `{
		"keys": [
			{"alg":"EdDSA","crv":"Ed25519","kid":"current","kty":"OKP","use":"sig",
			 "x":"iRjI0Qr9WRzkvTcY4bv8tAGPgBGrj83PSikHxaRFKyM"},
			{"alg":"EdDSA","crv":"Ed25519","kid":"previous","kty":"OKP","use":"sig",
			 "x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
		]
	}`
	set, err := jwk.ParseJWKS([]byte(doc))
	require.NoError(t, err)
	require.Len(t, set.Keys, 2)

	cur, ok := set.SigByKid("current")
	require.True(t, ok)
	assert.Equal(t, "iRjI0Qr9WRzkvTcY4bv8tAGPgBGrj83PSikHxaRFKyM", cur.X)

	prev, ok := set.SigByKid("previous")
	require.True(t, ok)
	assert.Equal(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", prev.X)

	for _, kid := range []string{"current", "previous"} {
		_, ok = set.EncByKid(kid)
		assert.False(t, ok, "kid %q must never resolve through EncByKid", kid)
	}
}

// TestParseJWKSMixedSigAndEncKeys asserts a set holding an Ed25519 sig key and
// an X25519 use:enc key parses, and that the two selectors never cross:
// SigByKid only ever resolves signing keys, EncByKid only ever resolves
// encryption keys, and an empty kid matches nothing on either selector.
func TestParseJWKSMixedSigAndEncKeys(t *testing.T) {
	const doc = `{"keys":[` + ed25519SigJWK + `,` + x25519EncJWK + `]}`
	set, err := jwk.ParseJWKS([]byte(doc))
	require.NoError(t, err)
	require.Len(t, set.Keys, 2)

	sig, ok := set.SigByKid("sig-current")
	require.True(t, ok, "the Ed25519 sig key must resolve through SigByKid")
	assert.Equal(t, "Ed25519", sig.Crv)

	enc, ok := set.EncByKid("enc-current")
	require.True(t, ok, "the X25519 use:enc key must resolve through EncByKid")
	assert.Equal(t, "X25519", enc.Crv)
	assert.Equal(t, "enc", enc.Use)

	_, ok = set.SigByKid("enc-current")
	assert.False(t, ok, "SigByKid must never return the X25519 key")
	_, ok = set.EncByKid("sig-current")
	assert.False(t, ok, "EncByKid must never return the Ed25519 key")
	_, ok = set.SigByKid("unknown-kid")
	assert.False(t, ok)
	_, ok = set.EncByKid("unknown-kid")
	assert.False(t, ok)
	_, ok = set.SigByKid("")
	assert.False(t, ok, "an empty kid must never match")
	_, ok = set.EncByKid("")
	assert.False(t, ok, "an empty kid must never match")
}

// TestParseKeyX25519UseEncOnly asserts OKP/X25519 keys parse only as
// encryption keys: use must be "enc" and alg, when present, must be
// "ECDH-ES"; anything else is rejected fail-closed, both per key and for
// a whole set containing it.
func TestParseKeyX25519UseEncOnly(t *testing.T) {
	const body = `"crv":"X25519","kty":"OKP","x":"` + x25519X + `"`
	accept := map[string]string{
		"use enc, alg ECDH-ES": `{"alg":"ECDH-ES","use":"enc",` + body + `}`,
		"use enc, alg absent":  `{"use":"enc",` + body + `}`,
	}
	for name, in := range accept {
		t.Run(name, func(t *testing.T) {
			key, err := jwk.ParseKey([]byte(in))
			require.NoError(t, err)
			assert.Equal(t, "X25519", key.Crv)
			assert.Equal(t, "enc", key.Use)
		})
	}
	reject := map[string]string{
		"use absent":          `{` + body + `}`,
		"use sig":             `{"use":"sig",` + body + `}`,
		"alg EdDSA":           `{"alg":"EdDSA","use":"enc",` + body + `}`,
		"alg ECDH-ES+A256GCM": `{"alg":"ECDH-ES+A256GCM","use":"enc",` + body + `}`,
		"crv P-256 use enc":   `{"crv":"P-256","kty":"OKP","use":"enc","x":"` + x25519X + `"}`,
	}
	for name, in := range reject {
		t.Run(name, func(t *testing.T) {
			_, err := jwk.ParseKey([]byte(in))
			assert.Error(t, err)
			_, err = jwk.ParseJWKS([]byte(`{"keys":[` + in + `]}`))
			assert.Error(t, err, "one rejected key must fail the whole set")
		})
	}
}

// TestParseKeyECP256 asserts an RFC 7515 Appendix A.1 EC key parses and its
// thumbprint matches the raw-JSON computation.
func TestParseKeyECP256(t *testing.T) {
	key, err := jwk.ParseKey([]byte(rfc7515AppendixA1JWK))
	require.NoError(t, err)
	assert.Equal(t, "EC", key.Kty)
	assert.Equal(t, "P-256", key.Crv)
	assert.Equal(t, "74c0d034-c1b1-44f8-8df2-8f1c4b19b1e8", key.Kid)

	thumbprint, err := key.Thumbprint()
	require.NoError(t, err)
	raw, err := jwk.Thumbprint([]byte(rfc7515AppendixA1JWK))
	require.NoError(t, err)
	assert.Equal(t, raw, thumbprint)
}

// TestParseJWKSRejectsMalformed asserts malformed or unsupported JWKS input is
// rejected fail-closed: one bad key fails the whole set.
func TestParseJWKSRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"not json":           `{"keys":`,
		"not an object":      `[{"kty":"OKP"}]`,
		"missing keys":       `{}`,
		"keys not array":     `{"keys":{"kty":"OKP"}}`,
		"key not object":     `{"keys":["OKP"]}`,
		"unknown kty":        `{"keys":[{"kty":"RSA"}]}`,
		"okp wrong crv":      `{"keys":[{"kty":"OKP","crv":"P-256","x":"w"}]}`,
		"okp missing x":      `{"keys":[{"kty":"OKP","crv":"Ed25519"}]}`,
		"okp x not b64url":   `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"a+b/c="}]}`,
		"okp x wrong size":   `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAA"}]}`,
		"okp alg mismatch":   `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"ES256","x":"iRjI0Qr9WRzkvTcY4bv8tAGPgBGrj83PSikHxaRFKyM"}]}`,
		"ec missing y":       `{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"}]}`,
		"ec alg mismatch":    `{"keys":[{"kty":"EC","crv":"P-256","alg":"EdDSA","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`,
		"second key invalid": `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"iRjI0Qr9WRzkvTcY4bv8tAGPgBGrj83PSikHxaRFKyM"},{"kty":"OKP","crv":"Ed25519","x":"AAAA"}]}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := jwk.ParseJWKS([]byte(in))
			assert.Error(t, err)
		})
	}
}
