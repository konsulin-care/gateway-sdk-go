package envelope

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// boundVersion is the wrapper "v" this package seals and accepts: any
// other version fails closed at open (SDKP-001).
const boundVersion = 1

// boundNonceBytes is the random nonce length SealBound generates for an
// empty Binding.Nonce: 16 bytes = 128 bits, the wire minimum.
const boundNonceBytes = 16

// maxBoundDataBytes is the largest wrapper data payload OpenBound accepts:
// 524288 bytes. Anything larger fails closed with nil data.
const maxBoundDataBytes = 524288

// Binding carries the delivery values SealBound writes into the bound
// envelope wrapper: From is the sending party id (delivery token sub), To
// the recipient party id (the token's single aud entry), Service the
// listing name invoked, IssuedAt the wrapper iat in Unix seconds (a zero
// time means seal time), and Nonce the replay nonce (empty means a fresh
// >=128-bit random base64url value is generated).
type Binding struct {
	// From is the wrapper "from": the sending party id.
	From string
	// To is the wrapper "to": the recipient party id.
	To string
	// Service is the wrapper "service": the listing name invoked.
	Service string
	// IssuedAt is the wrapper "iat"; zero means the seal time.
	IssuedAt time.Time
	// Nonce is the wrapper "nonce"; empty means generate a fresh value.
	Nonce string
}

// boundWrapper is the JSON wrapper sealed as the JWE plaintext of a bound
// envelope: {v, from, to, service, iat, nonce, data}. Data holds the
// application payload bytes; encoding/json renders them as a base64
// string inside the wrapper.
type boundWrapper struct {
	V       int    `json:"v"`
	From    string `json:"from"`
	To      string `json:"to"`
	Service string `json:"service"`
	Iat     int64  `json:"iat"`
	Nonce   string `json:"nonce"`
	Data    []byte `json:"data"`
}

// SealBound seals payload to the recipient's X25519 public key with the
// SDKP-001 bound envelope wrapper as the JWE plaintext: {v:1, from, to,
// service, iat, nonce, data} per the gateway's normative Bound Envelope
// convention, sealed by Seal (alg ECDH-ES, enc A256GCM). A zero
// Binding.IssuedAt is replaced with the seal time, and an empty
// Binding.Nonce is replaced with a fresh >=128-bit random base64url
// value, so every seal carries a usable iat and a unique nonce.
//
// Parameters: payload is the application payload placed in wrapper data;
// kid is the recipient key identifier published in the protected header;
// recipient is the recipient's X25519 use:enc public key; binding carries
// the wrapper from/to/service/iat/nonce values.
// Returns: the compact JWE string and nil, or an error. Fails closed on a
// nil recipient or empty kid — no wrapper ever leaves unprotected.
func SealBound(payload []byte, kid string, recipient *ecdh.PublicKey, binding Binding) (string, error) {
	issuedAt := binding.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}
	nonce := binding.Nonce
	if nonce == "" {
		generated, err := newBoundNonce()
		if err != nil {
			return "", err
		}
		nonce = generated
	}
	plaintext, err := json.Marshal(boundWrapper{
		V:       boundVersion,
		From:    binding.From,
		To:      binding.To,
		Service: binding.Service,
		Iat:     issuedAt.Unix(),
		Nonce:   nonce,
		Data:    payload,
	})
	if err != nil {
		return "", fmt.Errorf("envelope: SealBound: wrapper encode: %w", err)
	}
	return Seal(plaintext, kid, recipient)
}

// newBoundNonce generates the wrapper nonce for an empty Binding.Nonce:
// 16 random bytes rendered base64url (unpadded).
//
// Returns: the base64url nonce and nil, or an error. Errors carry no
// randomness or key material.
func newBoundNonce() (string, error) {
	raw := make([]byte, boundNonceBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("envelope: SealBound: nonce randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
