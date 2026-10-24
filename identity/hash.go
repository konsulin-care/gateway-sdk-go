package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// NAMarker is the gateway hashfmt marker for a non-applicable identity field.
// Hashing an empty (non-applicable) field returns this marker instead of a
// hash, matching the gateway's hashfmt convention (ADR-005).
const NAMarker = "N/A"

// pepperSize is the required size in bytes of the identity hashing pepper.
// The gateway enforces the same fixed size, so HMAC keying is uniform. It
// equals the HMAC-SHA256 output size, which is the decoded size a well-formed
// hashfmt value must have.
const pepperSize = 32

// ValidateHash reports whether value is acceptable under the gateway hashfmt
// convention (SDK-ID-002), mirroring the gateway's hashfmt.Validate: the
// N/A marker, or standard base64 (StdEncoding) decoding to exactly 32 bytes.
// The empty string, wrong-length decodes (31/33 bytes), URL-safe or otherwise
// invalid base64, and raw bytes are all rejected fail-closed before any wire
// use (ADR-011).
//
// Parameters:
//   - value: the candidate identity-hash string.
//
// Return value: nil when the value is valid, an error otherwise.
func ValidateHash(value string) error {
	if value == NAMarker {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != pepperSize {
		return fmt.Errorf("identity: hash must be %q or standard base64 of exactly %d bytes", NAMarker, pepperSize)
	}
	return nil
}

// Equal compares two hashfmt strings in constant time (crypto/subtle), so a
// compare never leaks how many leading bytes matched. It reports true only
// for byte-identical strings — including both being the N/A marker — and
// false for any difference in content or length.
//
// Parameters:
//   - a, b: the identity-hash strings to compare.
//
// Return value: true if and only if a and b are identical strings.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

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
