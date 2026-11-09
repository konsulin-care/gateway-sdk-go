package envelope

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// updateBoundFixture backs the regeneration command
// `go test ./envelope -run TestBoundDecryptVector -update`: with the flag
// the test first rewrites the committed fixture from the T19a
// deterministic seal path; without it the test only verifies the
// committed file.
var updateBoundFixture = flag.Bool("update", false,
	"rewrite envelope/testdata/bound-v1-decrypt.json from the deterministic seal path")

// boundDecryptFixturePath is the committed fixture this test verifies.
// It lives under envelope/testdata — never under testdata/golden.
const boundDecryptFixturePath = "testdata/bound-v1-decrypt.json"

// boundDecryptFixture is the on-disk shape of boundDecryptFixturePath:
// the fixed test-only recipient X25519 private key (hex), the compact
// JWE sealed through the T19a deterministic path, the expected plaintext
// wrapper, and the binding the wrapper was sealed with.
type boundDecryptFixture struct {
	RecipientPrivate string         `json:"recipientPrivate"`
	Compact          string         `json:"compact"`
	Plaintext        []byte         `json:"plaintext"`
	Binding          fixtureBinding `json:"binding"`
}

// fixtureBinding is the fixture's binding: iat is Unix seconds so the
// JSON stays a plain number.
type fixtureBinding struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Service string `json:"service"`
	Iat     int64  `json:"iat"`
	Nonce   string `json:"nonce"`
}

// fixtureRecipientPrivateHex returns the fixed test-only recipient
// X25519 private key of the decrypt fixture: SHA-256 over a fixed label,
// so regeneration always reproduces the same 32-byte scalar.
//
// Returns: the hex-encoded private scalar.
func fixtureRecipientPrivateHex() string {
	sum := sha256.Sum256([]byte("gateway-sdk-go envelope bound-v1-decrypt fixture recipient"))
	return hex.EncodeToString(sum[:])
}

// writeBoundDecryptFixture regenerates boundDecryptFixturePath through
// the T19a deterministic seal path: fixed recipient key, RFC 7748 Alice
// ephemeral, fixed IV randomness, a fully pinned binding, and the shared
// pepper-shaped payload, so the compact JWE and wrapper plaintext are
// byte-reproducible across runs.
//
// Parameters: t fails the test on any seal, marshal, or write error.
func writeBoundDecryptFixture(t *testing.T) {
	t.Helper()
	payload := pepperShapedPayload()
	recipient := x25519HexPrivate(t, fixtureRecipientPrivateHex())
	ephemeral := x25519HexPrivate(t, rfc7748AlicePriv)
	binding := Binding{
		From:     "party-seller",
		To:       "party-recipient",
		Service:  "consultation",
		IssuedAt: time.Unix(1700000000, 0),
		Nonce:    "m8TqmKz0qNqKz0qNqKz0qA",
	}
	compact, err := sealBound(payload, "vector-kid", recipient.PublicKey(),
		binding, ephemeral,
		bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}))
	require.NoError(t, err, "the deterministic bound seal must succeed")
	plaintext, err := json.Marshal(boundWrapper{
		V:       boundVersion,
		From:    binding.From,
		To:      binding.To,
		Service: binding.Service,
		Iat:     binding.IssuedAt.Unix(),
		Nonce:   binding.Nonce,
		Data:    payload,
	})
	require.NoError(t, err, "the wrapper plaintext must marshal")
	raw, err := json.MarshalIndent(boundDecryptFixture{
		RecipientPrivate: fixtureRecipientPrivateHex(),
		Compact:          compact,
		Plaintext:        plaintext,
		Binding: fixtureBinding{
			From:    binding.From,
			To:      binding.To,
			Service: binding.Service,
			Iat:     binding.IssuedAt.Unix(),
			Nonce:   binding.Nonce,
		},
	}, "", "  ")
	require.NoError(t, err, "the fixture must marshal")
	require.NoError(t, os.MkdirAll("testdata", 0o755), "testdata must exist")
	require.NoError(t, os.WriteFile(boundDecryptFixturePath, append(raw, '\n'), 0o644),
		"the fixture must be written")
}

// loadBoundDecryptFixture reads the committed decrypt fixture.
//
// Parameters: t fails the test when the fixture is missing or malformed.
// Returns: the parsed fixture.
func loadBoundDecryptFixture(t *testing.T) boundDecryptFixture {
	t.Helper()
	raw, err := os.ReadFile(boundDecryptFixturePath)
	require.NoError(t, err, "the decrypt fixture must be committed (regenerate with -update)")
	var fixture boundDecryptFixture
	require.NoError(t, json.Unmarshal(raw, &fixture), "the fixture must be valid JSON")
	require.NotEmpty(t, fixture.Compact, "the fixture must carry a compact JWE")
	require.NotEmpty(t, fixture.Plaintext, "the fixture must carry the expected plaintext")
	require.NotEmpty(t, fixture.RecipientPrivate, "the fixture must carry the recipient key")
	return fixture
}

// TestBoundDecryptVector verifies the committed bound-decrypt fixture at
// envelope/testdata/bound-v1-decrypt.json (never under testdata/golden):
// with -update the fixture is first rewritten from the T19a deterministic
// seal path; without the flag the test only verifies the committed file.
// Opening the fixture JWE with the fixture's X25519 private key must
// return the fixture plaintext byte-for-byte, and OpenBound with the
// fixture binding as Expectations and a clock at the fixture iat must
// return the fixture data.
func TestBoundDecryptVector(t *testing.T) {
	if *updateBoundFixture {
		writeBoundDecryptFixture(t)
	}
	fixture := loadBoundDecryptFixture(t)
	recipient := x25519HexPrivate(t, fixture.RecipientPrivate)

	opened, err := Open(fixture.Compact, recipient)
	require.NoError(t, err, "the fixture key must open the fixture JWE")
	assert.Equal(t, fixture.Plaintext, opened,
		"Open must return the fixture plaintext byte-for-byte")

	var wrapper boundWrapper
	require.NoError(t, json.Unmarshal(fixture.Plaintext, &wrapper),
		"the fixture plaintext must decode as the bound wrapper")

	iat := time.Unix(fixture.Binding.Iat, 0)
	clock := func() time.Time { return iat }
	exp := Expectations{
		From:    fixture.Binding.From,
		To:      fixture.Binding.To,
		Service: fixture.Binding.Service,
	}
	data, err := OpenBound(context.Background(), fixture.Compact, recipient, exp, nil, clock)
	require.NoError(t, err,
		"the fixture binding as expectations at a clock on the fixture iat must accept")
	assert.Equal(t, wrapper.Data, data, "OpenBound must return the fixture data")
}
