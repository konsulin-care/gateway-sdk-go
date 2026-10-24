package jwk_test

import (
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

	// Kid-only selection resolves the served key.
	selected, ok := set.ByKid(key.Kid)
	require.True(t, ok)
	assert.Equal(t, key, selected)
	_, ok = set.ByKid("unknown-kid")
	assert.False(t, ok)
	_, ok = set.ByKid("")
	assert.False(t, ok)
}

// TestParseJWKSHoldsCurrentAndPrevious asserts a rotation-overlap JWKS retains
// both the current and the previous key and selects each by kid only.
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

	cur, ok := set.ByKid("current")
	require.True(t, ok)
	assert.Equal(t, "iRjI0Qr9WRzkvTcY4bv8tAGPgBGrj83PSikHxaRFKyM", cur.X)

	prev, ok := set.ByKid("previous")
	require.True(t, ok)
	assert.Equal(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", prev.X)
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
