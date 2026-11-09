package envelope

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// errReplayCacheBoom is the canned failure the erroring ReplayCache fake
// returns from Check.
var errReplayCacheBoom = errors.New("replay cache unavailable")

// errorReplayCache is a wire.ReplayCache fake whose Check always fails,
// so tests can pin OpenBound's fail-closed handling of cache errors.
type errorReplayCache struct{}

// Compile-time assertion: the fake satisfies wire.ReplayCache.
var _ wire.ReplayCache = (*errorReplayCache)(nil)

// Check always fails with errReplayCacheBoom.
//
// Parameters: ctx carries caller cancellation; scope and key identify
// the pair; until is the reservation deadline.
// Returns: false and errReplayCacheBoom — never a fresh verdict.
func (c *errorReplayCache) Check(_ context.Context, _, _ string, _ time.Time) (bool, error) {
	return false, errReplayCacheBoom
}

// Release always fails with errReplayCacheBoom.
//
// Parameters: ctx carries caller cancellation; scope and key identify
// the pair.
// Returns: false and errReplayCacheBoom.
func (c *errorReplayCache) Release(_ context.Context, _, _ string) error {
	return errReplayCacheBoom
}

// sealWrapperWithNonce seals an arbitrary bound wrapper value as the JWE
// plaintext, so tests can pin nonce shapes SealBound would never produce
// (an empty nonce is always replaced by a fresh generated one).
//
// Parameters: t is the test helper; recipient is the sealing key pair;
// nonce is the wrapper nonce to seal verbatim.
// Returns: the compact JWE.
func sealWrapperWithNonce(t *testing.T, recipient *ecdh.PrivateKey, nonce string) string {
	t.Helper()
	plaintext, err := json.Marshal(boundWrapper{
		V:       boundVersion,
		From:    "party-seller",
		To:      "party-recipient",
		Service: "consultation",
		Iat:     time.Unix(1_700_000_000, 0).Unix(),
		Nonce:   nonce,
		Data:    pepperShapedPayload(),
	})
	require.NoError(t, err, "the wrapper must marshal")
	compact, err := Seal(plaintext, "bound-kid", recipient.PublicKey())
	require.NoError(t, err, "the wrapper must seal")
	return compact
}

// TestSealBoundNonceFormat pins the SDKP-001 nonce format generation:
// every SealBound call with an empty Binding.Nonce draws 16 bytes from
// crypto/rand and renders them as unpadded base64url, so each seal's
// nonce decodes to at least 16 bytes and no two seals share a nonce.
func TestSealBoundNonceFormat(t *testing.T) {
	recipient := newRecipient(t)
	binding := boundBinding()

	compact, err := SealBound(pepperShapedPayload(), "bound-kid", recipient.PublicKey(), binding)
	require.NoError(t, err, "the first seal must succeed")
	second, err := SealBound(pepperShapedPayload(), "bound-kid", recipient.PublicKey(), binding)
	require.NoError(t, err, "the second seal must succeed")

	firstNonce := wrapperOf(t, compact, recipient).Nonce
	secondNonce := wrapperOf(t, second, recipient).Nonce

	require.NotEmpty(t, firstNonce, "an empty Nonce must be generated at seal time")
	raw, err := base64.RawURLEncoding.DecodeString(firstNonce)
	require.NoError(t, err, "the nonce must be unpadded base64url")
	assert.GreaterOrEqual(t, len(raw), 16, "the nonce must decode to at least 16 bytes")
	assert.NotEqual(t, firstNonce, secondNonce, "each seal must generate a distinct nonce")
}

// TestOpenBoundRejectsMalformedNonce pins the SDKP-001 nonce format
// check: a wrapper carrying an empty nonce or a nonce longer than 64
// characters is rejected with nil data before the ReplayCache is ever
// consulted, while a 64-character nonce still passes the format check.
func TestOpenBoundRejectsMalformedNonce(t *testing.T) {
	recipient := newRecipient(t)
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	cases := map[string]string{
		"empty nonce":         "",
		"nonce over 64 chars": strings.Repeat("n", 65),
	}
	for name, nonce := range cases {
		t.Run(name, func(t *testing.T) {
			compact := sealWrapperWithNonce(t, recipient, nonce)
			cache := newRecordingReplayCache()

			data, err := OpenBound(context.Background(), compact, recipient, boundExpectations(), cache, clock)
			assert.Error(t, err, "a %s must be rejected", name)
			assert.Nil(t, data, "a rejected wrapper must return nil data")
			assert.Empty(t, cache.calls, "the format check must run before the cache is consulted")
		})
	}

	t.Run("64-char nonce passes the format check", func(t *testing.T) {
		compact := sealWrapperWithNonce(t, recipient, strings.Repeat("n", 64))
		cache := newRecordingReplayCache()

		data, err := OpenBound(context.Background(), compact, recipient, boundExpectations(), cache, clock)
		require.NoError(t, err, "a nonce of exactly 64 chars must be accepted")
		assert.Equal(t, pepperShapedPayload(), data,
			"an accepted wrapper must return its payload bytes")
		assert.NotEmpty(t, cache.calls, "an accepted nonce must be reserved in the cache")
	})
}

// TestOpenBoundNonceCacheErrorDenies pins the fail-closed cache rule: a
// non-nil ReplayCache whose Check returns an error denies the wrapper
// with nil data instead of accepting it.
func TestOpenBoundNonceCacheErrorDenies(t *testing.T) {
	recipient := newRecipient(t)
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	compact := sealWrapperWithNonce(t, recipient, "cache-error-nonce-0123456789")

	data, err := OpenBound(context.Background(), compact, recipient,
		boundExpectations(), &errorReplayCache{}, clock)
	assert.Error(t, err, "a failing ReplayCache must deny the wrapper")
	assert.Nil(t, data, "a cache failure must deny with nil data")
	assert.ErrorIs(t, err, errReplayCacheBoom, "the cache failure must surface to the caller")
}
