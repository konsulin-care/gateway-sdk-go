package jwk

import (
	"encoding/json"
	"errors"
	"fmt"
)

// KeySet is a parsed JSON Web Key Set (RFC 7517 section 5). A set served by
// the gateway holds the current signing key and, during rotation overlap, the
// previous one as well; both are retained here and selected by kid only via
// SigByKid, with X25519 use:enc recipient keys selected via EncByKid.
type KeySet struct {
	Keys []Key
}

// ParseJWKS parses a JWKS document.
//
// Parameters: data is the raw JSON encoding of the key set.
// Returns: the parsed KeySet and nil, or an error. Fail-closed: the document
// must be an object with a "keys" array and every element must be a valid
// key (see ParseKey); one invalid key fails the whole set.
func ParseJWKS(data []byte) (KeySet, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return KeySet{}, fmt.Errorf("jwk: parse JWKS: %w", err)
	}
	rawKeys, ok := doc["keys"]
	if !ok {
		return KeySet{}, errors.New(`jwk: parse JWKS: missing "keys"`)
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(rawKeys, &elems); err != nil {
		return KeySet{}, fmt.Errorf(`jwk: parse JWKS: "keys" must be an array: %w`, err)
	}
	keys := make([]Key, 0, len(elems))
	for i, elem := range elems {
		key, err := ParseKey(elem)
		if err != nil {
			return KeySet{}, fmt.Errorf("jwk: parse JWKS: key %d: %w", i, err)
		}
		keys = append(keys, key)
	}
	return KeySet{Keys: keys}, nil
}

// SigByKid selects a signing key (OKP/Ed25519 or EC/P-256) by kid only,
// never by alg or use. Encryption keys (OKP/X25519) never resolve here.
//
// Parameters: kid is the RFC 7638 thumbprint (or other kid) to look up.
// Returns: the matching signing key and true, or the zero Key and false. An
// empty kid never matches, so a key without a kid cannot be selected.
func (s KeySet) SigByKid(kid string) (Key, bool) {
	return s.selectBy(kid, isSigningKey)
}

// EncByKid selects an encryption key (OKP/X25519 with use "enc") by kid only.
// Signing keys never resolve here.
//
// Parameters: kid is the RFC 7638 thumbprint (or other kid) to look up.
// Returns: the matching encryption key and true, or the zero Key and false.
// An empty kid never matches, so a key without a kid cannot be selected.
func (s KeySet) EncByKid(kid string) (Key, bool) {
	return s.selectBy(kid, isEncryptionKey)
}

// selectBy returns the first key with the given kid that satisfies the kind
// predicate. An empty kid matches nothing.
func (s KeySet) selectBy(kid string, kind func(Key) bool) (Key, bool) {
	if kid == "" {
		return Key{}, false
	}
	for _, key := range s.Keys {
		if key.Kid == kid && kind(key) {
			return key, true
		}
	}
	return Key{}, false
}

// isSigningKey reports whether a key is usable for signatures: OKP/Ed25519
// or EC/P-256. X25519 encryption keys are excluded.
func isSigningKey(k Key) bool {
	return k.Crv == "Ed25519" || (k.Kty == "EC" && k.Crv == "P-256")
}

// isEncryptionKey reports whether a key is a JWE recipient key: OKP/X25519
// carrying use "enc" (ParseKey enforces that policy for every X25519 key).
func isEncryptionKey(k Key) bool {
	return k.Kty == "OKP" && k.Crv == "X25519" && k.Use == "enc"
}
