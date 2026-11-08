package envelope

import (
	"crypto/ecdh"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSelectRecipientEncKeySingleEncKey asserts SDKP-002: a JWKS holding
// exactly one use:enc X25519 key resolves to that public key and its kid.
func TestSelectRecipientEncKeySingleEncKey(t *testing.T) {
	recipient := newRecipient(t)
	doc := partyJWKS(t, recipient.PublicKey(), "recipient-enc")

	pub, kid, err := SelectRecipientEncKey(doc)
	require.NoError(t, err)
	require.NotNil(t, pub, "the selected key must be present")
	assert.Equal(t, "recipient-enc", kid,
		"the selected kid must be the use:enc key's kid")
	assert.True(t, pub.Equal(recipient.PublicKey()),
		"the selected key must equal the party's published use:enc key")
}

// TestSelectRecipientEncKeyNone asserts SDKP-002: a JWKS without any
// use:enc key fails closed with an error and a nil key.
func TestSelectRecipientEncKeyNone(t *testing.T) {
	sigOnly := jwksDoc(t, map[string]string{
		"alg": "EdDSA", "crv": "Ed25519", "kid": "sig-current", "kty": "OKP",
		"use": "sig", "x": "iRjI0Qr9WRzkvTcY4bv8tAGPgBGrj83PSikHxaRFKyM",
	})

	pub, kid, err := SelectRecipientEncKey(sigOnly)
	require.Error(t, err, "a JWKS without any use:enc key must fail closed")
	assert.Nil(t, pub, "a failed selection must return no key")
	assert.Empty(t, kid, "a failed selection must return no kid")
}

// TestSelectRecipientEncKeyAmbiguous asserts SDKP-002: a JWKS with two
// use:enc keys is ambiguous — error and a nil key, never a silent pick.
func TestSelectRecipientEncKeyAmbiguous(t *testing.T) {
	first := newRecipient(t)
	second := newRecipient(t)
	encKey := func(priv *ecdh.PrivateKey, kid string) map[string]string {
		return map[string]string{
			"alg": "ECDH-ES", "crv": "X25519", "kid": kid, "kty": "OKP",
			"use": "enc",
			"x":   base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		}
	}
	doc := jwksDoc(t, encKey(first, "enc-a"), encKey(second, "enc-b"))

	pub, kid, err := SelectRecipientEncKey(doc)
	require.Error(t, err, "two use:enc keys must be rejected as ambiguous")
	assert.Contains(t, err.Error(), "ambiguous",
		"the error must say the selection is ambiguous")
	assert.Nil(t, pub, "an ambiguous selection must return no key")
	assert.Empty(t, kid, "an ambiguous selection must return no kid")
}
