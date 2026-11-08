package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// ParseEd25519PrivateKey parses gateway cmd/genkey output into an Ed25519
// private key (SDKP-006): standard (padded) base64 wrapping either a 32-byte
// seed or an already-expanded 64-byte private key. A seed is expanded with
// ed25519.NewKeyFromSeed. Trailing line breaks from the generator output are
// tolerated. Fail-closed: anything else — malformed base64 or any other
// decoded length — is rejected. Errors carry only format and length facts;
// they never include the input string or any decoded key material.
//
// Parameters: s is the genkey output value (std base64).
// Returns: the private key and nil, or an error. Never panics.
func ParseEd25519PrivateKey(s string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimRight(s, "\r\n"))
	if err != nil {
		return nil, fmt.Errorf("auth: parse ed25519 private key: invalid base64: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf(
			"auth: parse ed25519 private key: decoded length is %d bytes, want %d (seed) or %d (private key)",
			len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}
