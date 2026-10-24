package identity_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/identity"
)

// testPepper is the fixed 32-byte test pepper for the SDK-ID-001 vectors.
// Test-only: production peppers are supplied by callers and never committed.
var testPepper = []byte("0123456789abcdef0123456789abcdef")

// wantHash computes the expected gateway hashfmt value for a normalized
// identity field: HMAC-SHA256 over the normalized value with the test pepper,
// rendered as standard base64 of exactly 32 bytes.
func wantHash(t *testing.T, normalized string) string {
	t.Helper()
	mac := hmac.New(sha256.New, testPepper)
	_, err := mac.Write([]byte(normalized))
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// TestIdentityHashfmtVectors asserts SDK-ID-001: email and phone
// normalization rules, and that valid inputs hash to the standard base64 of a
// 32-byte HMAC-SHA256 over the normalized value, while invalid inputs and a
// wrong-size pepper fail closed with an error and never a hash.
func TestIdentityHashfmtVectors(t *testing.T) {
	t.Run("normalize email trims and lowercases", func(t *testing.T) {
		got, err := identity.NormalizeEmail(" A@B.com ")
		require.NoError(t, err)
		assert.Equal(t, "a@b.com", got)
	})

	t.Run("normalize phone strips formatting to E.164 digits", func(t *testing.T) {
		got, err := identity.NormalizePhone("+62 812-3456-7890")
		require.NoError(t, err)
		assert.Equal(t, "6281234567890", got)

		same, err := identity.NormalizePhone("6281234567890")
		require.NoError(t, err)
		assert.Equal(t, got, same, "the E.164 digits alone must normalize identically")
	})

	t.Run("normalize phone rejects leading zero and wrong digit counts", func(t *testing.T) {
		reject := map[string]string{
			"leading zero": "081234567890",
			"too short":    "62812345",
			"too long":     "62812345678901234",
		}
		for name, in := range reject {
			t.Run(name, func(t *testing.T) {
				got, err := identity.NormalizePhone(in)
				assert.Error(t, err)
				assert.Empty(t, got, "a rejected phone must never produce a value")
			})
		}
	})

	t.Run("normalize email rejects malformed addresses", func(t *testing.T) {
		reject := []string{
			"no-at-sign.example",
			"a@@b.com",
			"@b.com",
			"a@",
			"a@.com",
		}
		for _, in := range reject {
			got, err := identity.NormalizeEmail(in)
			assert.Error(t, err, "input %q must be rejected", in)
			assert.Empty(t, got, "a rejected email must never produce a value")
		}
	})

	t.Run("hash email is HMAC-SHA256 of the normalized value", func(t *testing.T) {
		got, err := identity.HashEmail(" A@B.com ", testPepper)
		require.NoError(t, err)
		assert.Equal(t, wantHash(t, "a@b.com"), got)

		raw, err := base64.StdEncoding.DecodeString(got)
		require.NoError(t, err, "the hash must be standard base64 (StdEncoding)")
		assert.Len(t, raw, sha256.Size, "the hash must decode to exactly 32 bytes")

		same, err := identity.HashEmail("a@b.com", testPepper)
		require.NoError(t, err)
		assert.Equal(t, got, same, "raw input must hash over its normalized form")
	})

	t.Run("hash phone is HMAC-SHA256 of the normalized value", func(t *testing.T) {
		got, err := identity.HashPhone("+62 812-3456-7890", testPepper)
		require.NoError(t, err)
		assert.Equal(t, wantHash(t, "6281234567890"), got)

		raw, err := base64.StdEncoding.DecodeString(got)
		require.NoError(t, err, "the hash must be standard base64 (StdEncoding)")
		assert.Len(t, raw, sha256.Size, "the hash must decode to exactly 32 bytes")
	})

	t.Run("invalid input errors and never yields a hash", func(t *testing.T) {
		got, err := identity.HashEmail("not-an-email", testPepper)
		assert.Error(t, err)
		assert.Empty(t, got, "an invalid email must never produce a hash")

		got, err = identity.HashPhone("081234567890", testPepper)
		assert.Error(t, err)
		assert.Empty(t, got, "an invalid phone must never produce a hash")
	})

	t.Run("pepper must be exactly 32 bytes", func(t *testing.T) {
		badPeppers := map[string][]byte{
			"nil":   nil,
			"empty": {},
			"31":    testPepper[:31],
			"33":    append(append([]byte(nil), testPepper...), 0),
		}
		for name, pepper := range badPeppers {
			t.Run(name, func(t *testing.T) {
				got, err := identity.HashEmail("a@b.com", pepper)
				assert.Error(t, err)
				assert.Empty(t, got, "a bad pepper must never produce a hash")

				got, err = identity.HashPhone("6281234567890", pepper)
				assert.Error(t, err)
				assert.Empty(t, got, "a bad pepper must never produce a hash")
			})
		}
	})
}

// TestIdentityNAMarkerForNonApplicableFields asserts the gateway hashfmt N/A
// marker: hashing an empty (non-applicable) field returns the marker, never
// an error and never a hash over an empty value.
func TestIdentityNAMarkerForNonApplicableFields(t *testing.T) {
	assert.Equal(t, "N/A", identity.NAMarker, "the marker is the gateway hashfmt value")

	got, err := identity.HashEmail("", testPepper)
	require.NoError(t, err, "a non-applicable field is not an error")
	assert.Equal(t, identity.NAMarker, got)

	got, err = identity.HashPhone("", testPepper)
	require.NoError(t, err, "a non-applicable field is not an error")
	assert.Equal(t, identity.NAMarker, got)
}
