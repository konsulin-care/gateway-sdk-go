package identity_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
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

// TestHashFormatValidationAcceptsMarkerAndBase64 asserts SDK-ID-002's accept
// path: ValidateHash mirrors the gateway hashfmt rule and accepts the "N/A"
// marker and standard base64 of exactly 32 bytes — including a hash produced
// by this package — while Equal is true for identical strings (markers
// included) and false for differing ones.
func TestHashFormatValidationAcceptsMarkerAndBase64(t *testing.T) {
	require.Equal(t, "N/A", identity.NAMarker)
	require.NoError(t, identity.ValidateHash(identity.NAMarker), "the hashfmt marker must validate")

	sum := sha256.Sum256([]byte("sdk-id-002 accept vector"))
	valid := base64.StdEncoding.EncodeToString(sum[:])
	require.NoError(t, identity.ValidateHash(valid), "standard base64 of exactly 32 bytes must validate")

	otherSum := sha256.Sum256([]byte("sdk-id-002 other vector"))
	other := base64.StdEncoding.EncodeToString(otherSum[:])

	hashed, err := identity.HashEmail("a@b.com", testPepper)
	require.NoError(t, err)
	require.NoError(t, identity.ValidateHash(hashed), "a hash produced by HashEmail must validate")

	assert.True(t, identity.Equal(valid, valid), "identical strings must compare equal")
	assert.True(t, identity.Equal(identity.NAMarker, identity.NAMarker))
	assert.False(t, identity.Equal(valid, other), "equal-length strings with different content must differ")
	assert.False(t, identity.Equal(valid, ""), "a string never equals the empty one")
	assert.False(t, identity.Equal(valid, identity.NAMarker))
}

// TestHashFormatValidationRejectsMalformed asserts SDK-ID-002's deny path:
// ValidateHash rejects the empty string, hashes decoding to 31 or 33 bytes,
// URL-safe base64, invalid base64, and raw bytes — fail-closed before any
// wire use — and Equal never reports such a malformed value equal to the
// marker.
func TestHashFormatValidationRejectsMalformed(t *testing.T) {
	sum := sha256.Sum256([]byte("sdk-id-002 reject vector"))
	ff := make([]byte, 32)
	raw := make([]byte, 32)
	for i := range ff {
		ff[i] = 0xff
		raw[i] = byte(i) // 0x00..0x1f: none of these bytes is in the base64 alphabet
	}

	cases := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "31 decoded bytes", value: base64.StdEncoding.EncodeToString(sum[:31])},
		{name: "33 decoded bytes", value: base64.StdEncoding.EncodeToString(append(sum[:32:32], 0))},
		{name: "url-safe padded", value: base64.URLEncoding.EncodeToString(ff)},
		{name: "url-safe unpadded", value: base64.RawURLEncoding.EncodeToString(ff)},
		{name: "invalid base64", value: "not base64!!"},
		{name: "raw bytes", value: string(raw)},
		{name: "marker with padding", value: " N/A "},
		{name: "marker, wrong case", value: "n/a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Error(t, identity.ValidateHash(tc.value), "%q must be rejected fail-closed", tc.value)
			assert.False(t, identity.Equal(tc.value, identity.NAMarker), "a malformed value must never equal the marker")
		})
	}
}

// sharedVectors is the on-disk shape of identity/testdata/vectors.json: the
// fixed test pepper plus the shared input-to-expected-hash rows the backend
// adapter mirrors (SDK-ID-C01).
type sharedVectors struct {
	Pepper  string      `json:"pepper"`
	Vectors []sharedRow `json:"vectors"`
}

// sharedRow is one shared fixture vector: the raw identity input, its
// normalized form (empty on the N/A rows), and the expected gateway hashfmt
// value (the N/A marker or standard base64 of the 32-byte HMAC-SHA256).
type sharedRow struct {
	Name       string `json:"name"`
	Field      string `json:"field"`
	Input      string `json:"input"`
	Normalized string `json:"normalized"`
	Expected   string `json:"expected"`
}

// hashVector dispatches one fixture row to the matching identity hash
// function under the fixed test pepper.
func hashVector(field, input string) (string, error) {
	if field == "email" {
		return identity.HashEmail(input, testPepper)
	}
	return identity.HashPhone(input, testPepper)
}

// TestIdentitySharedFixtureVectors asserts SDK-ID-C01: every row of the
// shared fixture vectors in identity/testdata/vectors.json — email rows,
// phone rows, and the N/A marker cases — hashes byte-for-byte to its
// expected value under the fixed test pepper pinned by the file. The
// comparison is exact, so altering any input or expectation in the fixture
// fails this test.
func TestIdentitySharedFixtureVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors.json")
	require.NoError(t, err, "the shared fixture vectors must be committed")
	var doc sharedVectors
	require.NoError(t, json.Unmarshal(data, &doc), "vectors.json must be valid JSON")
	require.Equal(t, string(testPepper), doc.Pepper, "the vectors pin the shared fixed test pepper")
	require.NotEmpty(t, doc.Vectors, "the fixture must carry rows")

	for _, row := range doc.Vectors {
		t.Run(row.Name, func(t *testing.T) {
			require.Contains(t, []string{"email", "phone"}, row.Field, "row field must be email or phone")
			got, err := hashVector(row.Field, row.Input)
			require.NoError(t, err, "a fixture row input must normalize, or be empty")
			assert.Equal(t, row.Expected, got,
				"row %q must hash byte-for-byte to its expected value", row.Name)
			require.NoError(t, identity.ValidateHash(got), "every row value must satisfy hashfmt")
			if row.Input == "" {
				assert.Equal(t, identity.NAMarker, got, "an empty input is the N/A row")
				assert.Empty(t, row.Normalized, "an N/A row carries no normalized value")
				return
			}
			var wantNorm string
			if row.Field == "email" {
				wantNorm, err = identity.NormalizeEmail(row.Input)
			} else {
				wantNorm, err = identity.NormalizePhone(row.Input)
			}
			require.NoError(t, err)
			assert.Equal(t, row.Normalized, wantNorm, "row %q must pin its normalized form", row.Name)
			raw, err := base64.StdEncoding.DecodeString(got)
			require.NoError(t, err)
			assert.Len(t, raw, sha256.Size, "a hash row must be standard base64 of exactly 32 bytes")
		})
	}
}
