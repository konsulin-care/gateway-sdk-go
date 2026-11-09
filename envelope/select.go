package envelope

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"

	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
)

// SelectRecipientEncKey resolves the recipient's active use:enc key from a
// party JWKS document (as served by GET /v1/parties/{id}/jwks) when the
// sender does not know the key id in advance: the document must hold
// exactly one OKP/X25519 use:enc key. Selection is enumeration over the
// internal/jwk encryption keys, never by alg or by a sender-chosen hint,
// so a document with no use:enc key or with more than one (ambiguous)
// fails closed — no payload ever leaves unprotected. No jwk type is
// re-exported: only crypto/ecdh and the kid string cross this API.
//
// Parameters: jwks is the raw JSON JWKS document.
// Returns: the recipient's X25519 public key, its kid, and nil, or an
// error with a nil key and an empty kid.
func SelectRecipientEncKey(jwks []byte) (*ecdh.PublicKey, string, error) {
	set, err := jwk.ParseJWKS(jwks)
	if err != nil {
		return nil, "", fmt.Errorf("envelope: SelectRecipientEncKey: %w", err)
	}
	keys := set.EncKeys()
	if len(keys) == 0 {
		return nil, "", fmt.Errorf("envelope: SelectRecipientEncKey: no use:enc key in JWKS")
	}
	if len(keys) > 1 {
		return nil, "", fmt.Errorf("envelope: SelectRecipientEncKey: %d use:enc keys, ambiguous", len(keys))
	}
	key := keys[0]
	x, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, "", fmt.Errorf("envelope: SelectRecipientEncKey: kid %q: x decode: %w", key.Kid, err)
	}
	pub, err := ecdh.X25519().NewPublicKey(x)
	if err != nil {
		return nil, "", fmt.Errorf("envelope: SelectRecipientEncKey: kid %q: X25519 public key: %w", key.Kid, err)
	}
	return pub, key.Kid, nil
}
