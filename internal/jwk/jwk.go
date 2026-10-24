package jwk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// pointSizeBytes is the size in bytes of one Ed25519 public key or one P-256
// coordinate (both 256-bit curves).
const pointSizeBytes = 32

// Key is a parsed JWK (RFC 7517 section 2) for the only key types this SDK
// accepts: OKP/Ed25519 and EC/P-256 signing keys, plus OKP/X25519 keys used
// as encryption keys only (use "enc"). Unknown members are ignored.
type Key struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ParseKey parses and validates a single JWK (RFC 7517 section 4).
//
// Parameters: data is the raw JSON encoding of one JWK.
// Returns: the parsed Key and nil, or an error. Fail-closed: only OKP/Ed25519,
// OKP/X25519, and EC/P-256 keys parse; crv must match kty, x (and y for EC)
// must be base64url (unpadded) strings decoding to exactly 32 bytes, and a
// present alg must be EdDSA for OKP/Ed25519, ECDH-ES for OKP/X25519, or
// ES256 for EC. An X25519 key additionally requires use "enc".
func ParseKey(data []byte) (Key, error) {
	var key Key
	if err := json.Unmarshal(data, &key); err != nil {
		return Key{}, fmt.Errorf("jwk: parse key: %w", err)
	}
	if err := key.validate(); err != nil {
		return Key{}, err
	}
	return key, nil
}

// Thumbprint returns the RFC 7638 thumbprint of the key; for both OKP and EC
// keys the required members are crv, kty, and x.
//
// Returns: the base64url (unpadded) thumbprint and nil, or an error when the
// key is incomplete or its kty is unsupported.
func (k Key) Thumbprint() (string, error) {
	obj, err := json.Marshal(map[string]string{"crv": k.Crv, "kty": k.Kty, "x": k.X})
	if err != nil {
		return "", fmt.Errorf("jwk: key thumbprint: %w", err)
	}
	return Thumbprint(obj)
}

// validate enforces the fail-closed rules for the supported key types.
func (k *Key) validate() error {
	switch k.Kty {
	case "OKP":
		return k.validateOKP()
	case "EC":
		return k.validateEC()
	default:
		return fmt.Errorf("jwk: unsupported kty %q", k.Kty)
	}
}

// validateOKP enforces the fail-closed rules for OKP keys: Ed25519 for
// signatures and X25519 as an encryption key only (use "enc").
func (k *Key) validateOKP() error {
	switch k.Crv {
	case "Ed25519":
		return k.validateEd25519()
	case "X25519":
		return k.validateX25519()
	default:
		return fmt.Errorf("jwk: OKP key: unsupported crv %q", k.Crv)
	}
}

// validateEd25519 enforces the fail-closed rules for OKP/Ed25519 keys.
func (k *Key) validateEd25519() error {
	if err := decodeCoordinate(k.X); err != nil {
		return fmt.Errorf("jwk: OKP key: %w", err)
	}
	if k.Alg != "" && k.Alg != "EdDSA" {
		return fmt.Errorf("jwk: OKP key: alg %q does not match Ed25519", k.Alg)
	}
	return nil
}

// validateX25519 enforces the fail-closed rules for OKP/X25519 keys: they are
// JWE recipient keys only, so use must be "enc" and a present alg must be
// "ECDH-ES" (the JWE Envelope key-agreement algorithm).
func (k *Key) validateX25519() error {
	if k.Use != "enc" {
		return fmt.Errorf("jwk: OKP/X25519 key: use must be %q, got %q", "enc", k.Use)
	}
	if k.Alg != "" && k.Alg != "ECDH-ES" {
		return fmt.Errorf("jwk: OKP/X25519 key: alg %q does not match ECDH-ES", k.Alg)
	}
	if err := decodeCoordinate(k.X); err != nil {
		return fmt.Errorf("jwk: OKP/X25519 key: %w", err)
	}
	return nil
}

// validateEC enforces the fail-closed rules for EC/P-256 keys.
func (k *Key) validateEC() error {
	if k.Crv != "P-256" {
		return fmt.Errorf("jwk: EC key: unsupported crv %q", k.Crv)
	}
	if err := decodeCoordinate(k.X); err != nil {
		return fmt.Errorf("jwk: EC key: %w", err)
	}
	if err := decodeCoordinate(k.Y); err != nil {
		return fmt.Errorf("jwk: EC key: %w", err)
	}
	if k.Alg != "" && k.Alg != "ES256" {
		return fmt.Errorf("jwk: EC key: alg %q does not match ES256", k.Alg)
	}
	return nil
}

// decodeCoordinate validates one base64url (unpadded) curve coordinate.
func decodeCoordinate(s string) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("coordinate is not base64url: %w", err)
	}
	if len(b) != pointSizeBytes {
		return fmt.Errorf("coordinate is %d bytes, want %d", len(b), pointSizeBytes)
	}
	return nil
}
