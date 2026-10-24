package envelope

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwksDoc marshals the given JWK entries into a JWKS document, the shape
// served by GET /v1/parties/{id}/jwks.
func jwksDoc(t *testing.T, keys ...map[string]string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"keys": keys})
	require.NoError(t, err)
	return raw
}

// partyJWKS builds a party JWKS document holding one Ed25519 sig key plus
// the recipient's X25519 use:enc key published under kid.
func partyJWKS(t *testing.T, enc *ecdh.PublicKey, kid string) []byte {
	t.Helper()
	sigKey := map[string]string{
		"alg": "EdDSA", "crv": "Ed25519", "kid": "sig-current", "kty": "OKP",
		"use": "sig", "x": "iRjI0Qr9WRzkvTcY4bv8tAGPgBGrj83PSikHxaRFKyM",
	}
	encKey := map[string]string{
		"alg": "ECDH-ES", "crv": "X25519", "kid": kid, "kty": "OKP",
		"use": "enc", "x": base64.RawURLEncoding.EncodeToString(enc.Bytes()),
	}
	return jwksDoc(t, sigKey, encKey)
}

// TestSealRecipientEncKeyDiscovery asserts SDK-ENV-002 accept: SelectEncKey
// discovers the recipient's use:enc key in a party JWKS by kid, the
// discovered key equals the recipient's published X25519 public key, and a
// payload sealed to it opens byte-identical with the matching private key.
func TestSealRecipientEncKeyDiscovery(t *testing.T) {
	recipient := newRecipient(t)
	doc := partyJWKS(t, recipient.PublicKey(), "recipient-enc")

	pub, err := SelectEncKey(doc, "recipient-enc")
	require.NoError(t, err)
	require.NotNil(t, pub, "the discovered key must be present")
	assert.True(t, pub.Equal(recipient.PublicKey()),
		"the discovered key must equal the recipient's published use:enc key")

	payload := []byte(`{"direct":"exchange payload"}`)
	compact, err := Seal(payload, "recipient-enc", pub)
	require.NoError(t, err)

	opened, err := Open(compact, recipient)
	require.NoError(t, err)
	assert.Equal(t, payload, opened,
		"a payload sealed to the discovered key must open with the recipient's private key")
}

// TestSealUnknownEncKidFailsClosed asserts SDK-ENV-002 deny: an unknown kid,
// an empty kid, a kid pointing at the sig key, a JWKS holding only a sig key,
// an X25519 key without use:enc, and an unparseable JWKS each fail closed
// with an error and no key — so no payload ever leaves unprotected.
func TestSealUnknownEncKidFailsClosed(t *testing.T) {
	recipient := newRecipient(t)
	encX := base64.RawURLEncoding.EncodeToString(recipient.PublicKey().Bytes())
	sigKey := map[string]string{
		"alg": "EdDSA", "crv": "Ed25519", "kid": "sig-current", "kty": "OKP",
		"use": "sig", "x": "iRjI0Qr9WRzkvTcY4bv8tAGPgBGrj83PSikHxaRFKyM",
	}
	encKey := map[string]string{
		"alg": "ECDH-ES", "crv": "X25519", "kid": "recipient-enc", "kty": "OKP",
		"use": "enc", "x": encX,
	}
	encNoUse := map[string]string{
		"crv": "X25519", "kid": "recipient-enc", "kty": "OKP", "x": encX,
	}
	mixed := jwksDoc(t, sigKey, encKey)

	cases := []struct {
		name string
		doc  []byte
		kid  string
	}{
		{"unknown kid", mixed, "no-such-kid"},
		{"empty kid", mixed, ""},
		{"kid points at the sig key", mixed, "sig-current"},
		{"jwks with only a sig key", jwksDoc(t, sigKey), "sig-current"},
		{"x25519 without use:enc", jwksDoc(t, encNoUse), "recipient-enc"},
		{"malformed jwks", []byte(`{"keys":`), "recipient-enc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := SelectEncKey(tc.doc, tc.kid)
			assert.Error(t, err)
			assert.Nil(t, key, "a failed discovery must return no key")
		})
	}

	// A nil discovered key must also stop Seal: nothing leaves unprotected.
	key, err := SelectEncKey(mixed, "no-such-kid")
	require.Error(t, err)
	require.Nil(t, key)
	_, err = Seal([]byte("payload"), "no-such-kid", key)
	assert.Error(t, err, "Seal to a nil discovered key must fail closed")
}
