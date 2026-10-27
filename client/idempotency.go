package client

import (
	"crypto/rand"
	"fmt"
)

// newIdempotencyKey generates one fresh Idempotency-Key for one logical
// create (SDK-CLIENT-002, ADR-011): 16 crypto/rand bytes laid out as a
// UUIDv4 (version/variant nibbles set) and formatted lowercase hex with
// dashes. Entropy failure fails the call instead of weakening the key
// (fail closed). Returns: the key, or an error.
func newIdempotencyKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("client: generate idempotency key: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
