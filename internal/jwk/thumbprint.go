package jwk

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Thumbprint computes the RFC 7638 SHA-256 thumbprint of a JWK.
//
// Parameters: jwkJSON is the raw JSON encoding of a single JWK.
// Returns: the base64url (unpadded) thumbprint and nil, or an error when the
// input is not a JSON object or a required member (RFC 7638 section 3.2 per
// kty) is missing or not a string. Extra members never influence the result.
func Thumbprint(jwkJSON []byte) (string, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(jwkJSON, &obj); err != nil {
		return "", fmt.Errorf("jwk: thumbprint: %w", err)
	}
	rawKty, ok := obj["kty"]
	if !ok {
		return "", errors.New(`jwk: thumbprint: missing "kty"`)
	}
	var kty string
	if err := json.Unmarshal(rawKty, &kty); err != nil {
		return "", fmt.Errorf(`jwk: thumbprint: "kty" must be a string: %w`, err)
	}
	members, err := thumbprintMembers(kty)
	if err != nil {
		return "", err
	}
	canon := make(map[string]string, len(members))
	for _, m := range members {
		raw, ok := obj[m]
		if !ok {
			return "", fmt.Errorf("jwk: thumbprint: %q missing required member %q", kty, m)
		}
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return "", fmt.Errorf("jwk: thumbprint: member %q must be a string: %w", m, err)
		}
		canon[m] = v
	}
	sum, err := canonicalSHA256(canon)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// thumbprintMembers returns the RFC 7638 section 3.2 required members for kty.
func thumbprintMembers(kty string) ([]string, error) {
	switch kty {
	case "RSA":
		return []string{"e", "kty", "n"}, nil
	case "EC", "OKP":
		return []string{"crv", "kty", "x"}, nil
	case "oct":
		return []string{"k"}, nil
	default:
		return nil, fmt.Errorf("jwk: thumbprint: unsupported kty %q", kty)
	}
}

// canonicalSHA256 hashes the required members as canonical JSON: members in
// lexicographic order, string values, no whitespace (RFC 7638 section 3.1).
func canonicalSHA256(members map[string]string) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	keys := make([]string, 0, len(members))
	for k := range members {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := json.Marshal(k)
		if err != nil {
			return zero, fmt.Errorf("jwk: thumbprint: canonical member %q: %w", k, err)
		}
		value, err := json.Marshal(members[k])
		if err != nil {
			return zero, fmt.Errorf("jwk: thumbprint: canonical value for %q: %w", k, err)
		}
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteByte('}')
	return sha256.Sum256(buf.Bytes()), nil
}
