package jwk

import (
	"encoding/json"
	"errors"
	"fmt"
)

// KeySet is a parsed JSON Web Key Set (RFC 7517 section 5). A set served by
// the gateway holds the current signing key and, during rotation overlap, the
// previous one as well; both are retained here and selected by kid only.
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

// ByKid selects a key by kid only, never by alg or use.
//
// Parameters: kid is the RFC 7638 thumbprint (or other kid) to look up.
// Returns: the matching key and true, or the zero Key and false. An empty
// kid never matches, so a key without a kid cannot be selected.
func (s KeySet) ByKid(kid string) (Key, bool) {
	if kid == "" {
		return Key{}, false
	}
	for _, key := range s.Keys {
		if key.Kid == kid {
			return key, true
		}
	}
	return Key{}, false
}
