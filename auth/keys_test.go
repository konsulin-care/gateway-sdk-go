package auth_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/auth"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
)

// readGoldenKey returns the decoded std-base64 contents of
// testdata/golden/testonly-party-private.key (the gateway genkey output).
func readGoldenKey(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../testdata/golden/testonly-party-private.key")
	require.NoError(t, err)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	require.NoError(t, err)
	return raw
}

// TestParseEd25519PrivateKeyGoldenKid asserts the genkey-format golden key
// (SDKP-006) parses into a key that signs the ks-party fixture claims with a
// header kid equal to the kid pinned in testdata/golden/ks-party.json.
func TestParseEd25519PrivateKeyGoldenKid(t *testing.T) {
	golden, err := os.ReadFile("../testdata/golden/ks-party.json")
	require.NoError(t, err)
	var fixture goldenKSParty
	require.NoError(t, json.Unmarshal(golden, &fixture))
	goldenHdr, _, _, err := jws.Parse([]byte(fixture.JWT))
	require.NoError(t, err)
	require.NotEmpty(t, goldenHdr.Kid)

	keyB64, err := os.ReadFile("../testdata/golden/testonly-party-private.key")
	require.NoError(t, err)
	priv, err := auth.ParseEd25519PrivateKey(string(keyB64))
	require.NoError(t, err)
	require.Len(t, priv, ed25519.PrivateKeySize)

	tok, err := auth.SignPartyRequest(priv, fixture.Claims)
	require.NoError(t, err)
	hdr, _, _, err := jws.Parse([]byte(tok))
	require.NoError(t, err)
	assert.Equal(t, goldenHdr.Kid, hdr.Kid)
}

// TestParseEd25519PrivateKeySeedForm asserts the 32-byte seed form of the
// same key parses to a private key identical to the 64-byte form.
func TestParseEd25519PrivateKeySeedForm(t *testing.T) {
	full := readGoldenKey(t)
	require.Len(t, full, ed25519.PrivateKeySize)

	fromFull, err := auth.ParseEd25519PrivateKey(
		base64.StdEncoding.EncodeToString(full))
	require.NoError(t, err)

	seedB64 := base64.StdEncoding.EncodeToString(full[:ed25519.SeedSize])
	fromSeed, err := auth.ParseEd25519PrivateKey(seedB64)
	require.NoError(t, err)

	assert.Equal(t, fromFull, fromSeed)
	assert.Equal(t, ed25519.NewKeyFromSeed(full[:ed25519.SeedSize]), fromSeed)
}

// TestParseEd25519PrivateKeyErrorsOmitInput asserts malformed base64 and
// truncated inputs fail closed with errors that never echo the input string.
func TestParseEd25519PrivateKeyErrorsOmitInput(t *testing.T) {
	full := readGoldenKey(t)

	cases := []struct {
		name string
		in   string
	}{
		{"malformed base64", "@@@this-is-not-base64@@@"},
		{"truncated 64-byte key",
			base64.StdEncoding.EncodeToString(full[:len(full)-1])},
		{"truncated seed",
			base64.StdEncoding.EncodeToString(full[:ed25519.SeedSize-1])},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := auth.ParseEd25519PrivateKey(tc.in)
			require.Error(t, err)
			assert.Nil(t, key)
			assert.NotContains(t, err.Error(), tc.in)
		})
	}
}
