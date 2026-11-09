package envelope

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSealBoundDeterministicVector pins the test-only deterministic seal
// path: sealing the same payload with the same fixed ephemeral key and
// fixed randomness produces byte-identical compact JWEs, and the
// deterministic ciphertext opens with Open to the expected plaintext.
func TestSealBoundDeterministicVector(t *testing.T) {
	recipient := newRecipient(t)
	payload := pepperShapedPayload()
	ephemeral := x25519HexPrivate(t, rfc7748AlicePriv)
	binding := Binding{
		From:     "party-seller",
		To:       "party-recipient",
		Service:  "consultation",
		IssuedAt: time.Unix(1700000000, 0),
		Nonce:    "m8TqmKz0qNqKz0qNqKz0qA",
	}
	// freshReader replays the same fixed 12-byte IV randomness per seal.
	freshReader := func() io.Reader {
		return bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	}

	first, err := sealBound(payload, "vector-kid", recipient.PublicKey(),
		binding, ephemeral, freshReader())
	require.NoError(t, err)
	second, err := sealBound(payload, "vector-kid", recipient.PublicKey(),
		binding, ephemeral, freshReader())
	require.NoError(t, err)
	assert.Equal(t, first, second,
		"the same payload with the same fixed ephemeral and fixed randomness "+
			"must seal byte-identical compact JWEs")

	opened, err := Open(first, recipient)
	require.NoError(t, err)
	expected, err := json.Marshal(boundWrapper{
		V:       boundVersion,
		From:    binding.From,
		To:      binding.To,
		Service: binding.Service,
		Iat:     binding.IssuedAt.Unix(),
		Nonce:   binding.Nonce,
		Data:    payload,
	})
	require.NoError(t, err)
	assert.Equal(t, expected, opened,
		"the deterministic ciphertext must open with Open to the expected plaintext")
}
