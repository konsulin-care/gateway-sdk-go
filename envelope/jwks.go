package envelope

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"

	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
)

// SelectEncKey discovers a recipient's encryption key in a party JWKS
// document (as served by GET /v1/parties/{id}/jwks) and returns it ready
// for Seal. Selection is kid-only via the internal/jwk encryption-key
// selector: the key must be OKP/X25519 carrying use "enc" (jwk.ParseJWKS
// enforces that policy), so an unknown kid, an empty kid, a kid pointing
// at a signing key, an X25519 key without use:enc, or an unparseable
// document all fail closed — no payload ever leaves unprotected. No jwk
// type is re-exported: only crypto/ecdh crosses this API.
//
// Parameters: jwks is the raw JSON JWKS document; kid is the JWE header
// kid to select.
// Returns: the recipient's X25519 public key and nil, or an error with a
// nil key.
func SelectEncKey(jwks []byte, kid string) (*ecdh.PublicKey, error) {
	x, err := encKeyByKid(jwks, kid)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(x)
	if err != nil {
		return nil, fmt.Errorf("envelope: SelectEncKey: kid %q: X25519 public key: %w", kid, err)
	}
	return pub, nil
}

// encKeyByKid parses jwks fail-closed and returns the raw X25519 public
// coordinate of the use:enc key selected by kid only. An empty kid never
// matches, so a key without a kid cannot be selected.
func encKeyByKid(jwks []byte, kid string) ([]byte, error) {
	set, err := jwk.ParseJWKS(jwks)
	if err != nil {
		return nil, fmt.Errorf("envelope: SelectEncKey: %w", err)
	}
	key, ok := set.EncByKid(kid)
	if !ok {
		return nil, fmt.Errorf("envelope: SelectEncKey: no use:enc key for kid %q", kid)
	}
	x, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("envelope: SelectEncKey: kid %q: x decode: %w", kid, err)
	}
	return x, nil
}
