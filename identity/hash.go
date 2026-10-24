package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// NAMarker is the gateway hashfmt marker for a non-applicable identity field.
// Hashing an empty (non-applicable) field returns this marker instead of a
// hash, matching the gateway's hashfmt convention (ADR-005).
const NAMarker = "N/A"

// pepperSize is the required size in bytes of the identity hashing pepper.
// The gateway enforces the same fixed size, so HMAC keying is uniform.
const pepperSize = 32

// HashEmail computes the gateway hashfmt identity hash for an email field:
// the input is normalized with NormalizeEmail and hashed as
// HMAC-SHA256(normalized, pepper), rendered as standard base64 of exactly 32
// bytes. An empty (non-applicable) input returns NAMarker with no error; an
// invalid input or a pepper that is not exactly 32 bytes fails closed with an
// error and never a hash.
//
// Parameters:
//   - raw: the email as supplied by the caller; "" marks the field as
//     non-applicable.
//   - pepper: the caller-held HMAC pepper, exactly 32 bytes.
//
// Return value: the base64 hash or NAMarker, or an error on invalid input or
// a wrong-size pepper.
func HashEmail(raw string, pepper []byte) (string, error) {
	if raw == "" {
		return NAMarker, nil
	}
	normalized, err := NormalizeEmail(raw)
	if err != nil {
		return "", err
	}
	return hashNormalized(normalized, pepper)
}

// HashPhone computes the gateway hashfmt identity hash for a phone field: the
// input is normalized with NormalizePhone and hashed as
// HMAC-SHA256(normalized, pepper), rendered as standard base64 of exactly 32
// bytes. An empty (non-applicable) input returns NAMarker with no error; an
// invalid input or a pepper that is not exactly 32 bytes fails closed with an
// error and never a hash.
//
// Parameters:
//   - raw: the phone as supplied by the caller; "" marks the field as
//     non-applicable.
//   - pepper: the caller-held HMAC pepper, exactly 32 bytes.
//
// Return value: the base64 hash or NAMarker, or an error on invalid input or
// a wrong-size pepper.
func HashPhone(raw string, pepper []byte) (string, error) {
	if raw == "" {
		return NAMarker, nil
	}
	normalized, err := NormalizePhone(raw)
	if err != nil {
		return "", err
	}
	return hashNormalized(normalized, pepper)
}

// hashNormalized computes HMAC-SHA256 over a normalized identity value with
// the pepper and renders it as standard base64 of exactly 32 bytes.
//
// Parameters:
//   - normalized: the already-normalized identity value to hash.
//   - pepper: the caller-held HMAC pepper, exactly 32 bytes.
//
// Return value: the base64-encoded 32-byte HMAC, or an error if the pepper is
// not exactly 32 bytes.
func hashNormalized(normalized string, pepper []byte) (string, error) {
	if len(pepper) != pepperSize {
		return "", fmt.Errorf("identity: pepper must be exactly %d bytes, got %d", pepperSize, len(pepper))
	}
	mac := hmac.New(sha256.New, pepper)
	if _, err := mac.Write([]byte(normalized)); err != nil {
		return "", fmt.Errorf("identity: hash write: %w", err)
	}
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
