package envelope

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// x25519PrivateKeySize is the byte length of an X25519 private scalar.
const x25519PrivateKeySize = 32

// ParseX25519PrivateKey parses gateway cmd/genkey output into an X25519
// private key (SDKP-006): standard (padded) base64 wrapping exactly 32
// bytes. Trailing line breaks from the generator output are tolerated.
// Fail-closed: malformed base64 or any other decoded length is rejected.
// Errors carry only format and length facts; they never include the input
// string or any decoded key material.
//
// Parameters: s is the key value (std base64).
// Returns: the private key and nil, or an error. Never panics.
func ParseX25519PrivateKey(s string) (*ecdh.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimRight(s, "\r\n"))
	if err != nil {
		return nil, fmt.Errorf("envelope: ParseX25519PrivateKey: invalid base64: %w", err)
	}
	if len(raw) != x25519PrivateKeySize {
		return nil, fmt.Errorf(
			"envelope: ParseX25519PrivateKey: decoded length is %d bytes, want %d",
			len(raw), x25519PrivateKeySize)
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("envelope: ParseX25519PrivateKey: %w", err)
	}
	return key, nil
}

// EncJWK renders an X25519 public key as the use:enc JWK entry a party
// publishes in its JWKS (SDKP-006): kty OKP, crv X25519, use enc, x the
// base64url (unpadded) public coordinate, and kid the RFC 7638 thumbprint
// of the key — never a caller-supplied value. Errors carry no key material.
//
// Parameters: pub is the X25519 public key; nil or a non-X25519 key is
// rejected.
// Returns: the wire JWK and nil, or an error with a zero JWK.
func EncJWK(pub *ecdh.PublicKey) (wire.JWK, error) {
	if pub == nil {
		return wire.JWK{}, fmt.Errorf("envelope: EncJWK: nil public key")
	}
	if pub.Curve() != ecdh.X25519() {
		return wire.JWK{}, fmt.Errorf("envelope: EncJWK: public key is not X25519")
	}
	x := base64.RawURLEncoding.EncodeToString(pub.Bytes())
	kid, err := (jwk.Key{Kty: "OKP", Crv: "X25519", X: x}).Thumbprint()
	if err != nil {
		return wire.JWK{}, fmt.Errorf("envelope: EncJWK: kid: %w", err)
	}
	return wire.JWK{
		Kty: "OKP",
		Crv: "X25519",
		Kid: kid,
		X:   x,
		Use: "enc",
	}, nil
}
