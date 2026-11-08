package envelope

import (
	"context"
	"crypto/ecdh"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// replayCall records one ReplayCache.Check invocation so tests can pin
// the scope, key, and reservation deadline OpenBound used.
type replayCall struct {
	scope string
	key   string
	until time.Time
}

// recordingReplayCache is a deterministic wire.ReplayCache fake: Check
// records every call and atomically reserves (scope, key), so tests can
// assert both the replay verdict and the reservation window offline.
type recordingReplayCache struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	calls []replayCall
}

// Compile-time assertion: the fake satisfies wire.ReplayCache.
var _ wire.ReplayCache = (*recordingReplayCache)(nil)

// newRecordingReplayCache returns an empty, concurrency-safe fake cache.
//
// Returns: a ready-to-use recording cache.
func newRecordingReplayCache() *recordingReplayCache {
	return &recordingReplayCache{seen: make(map[string]struct{})}
}

// Check records the call and reserves (scope, key): a fresh pair returns
// true, a live pair false, and errors never — the real contract.
//
// Parameters: ctx carries caller cancellation; scope and key identify the
// pair; until is the reservation deadline.
// Returns: true when fresh, false on replay, nil error.
func (c *recordingReplayCache) Check(_ context.Context, scope, key string, until time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, replayCall{scope: scope, key: key, until: until})
	pair := scope + "\x00" + key
	if _, live := c.seen[pair]; live {
		return false, nil
	}
	c.seen[pair] = struct{}{}
	return true, nil
}

// Release frees a (scope, key) reservation so retries are not deduped.
//
// Parameters: ctx carries caller cancellation; scope and key as Check.
// Returns: nil.
func (c *recordingReplayCache) Release(_ context.Context, scope, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.seen, scope+"\x00"+key)
	return nil
}

// lastCall returns the most recent Check record and requires at least
// one call to have happened.
//
// Parameters: t is the test that fails when no Check was recorded.
// Returns: the last recorded call.
func (c *recordingReplayCache) lastCall(t *testing.T) replayCall {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.NotEmpty(t, c.calls, "OpenBound must reserve the nonce in the replay cache")
	return c.calls[len(c.calls)-1]
}

// sealBoundNonce seals pepperShapedPayload through SealBound with the
// given from and nonce pinned to iat, so replay tests control both
// halves of the (from, nonce) key exactly.
//
// Parameters: t is the test helper; recipient is the sealing key pair;
// from and nonce are the wrapper values; iat is the wrapper issued-at.
// Returns: the compact JWE.
func sealBoundNonce(t *testing.T, recipient *ecdh.PrivateKey, from, nonce string, iat time.Time) string {
	t.Helper()
	binding := boundBinding()
	binding.From = from
	binding.Nonce = nonce
	binding.IssuedAt = iat
	compact, err := SealBound(pepperShapedPayload(), "bound-kid", recipient.PublicKey(), binding)
	require.NoError(t, err)
	return compact
}

// boundExpectationsFrom returns the shared expectations with From set to
// the given sender, so each wrapper opens under its own sender's rules.
//
// Parameters: from is the expected wrapper sender.
// Returns: the matching expectations.
func boundExpectationsFrom(from string) Expectations {
	exp := boundExpectations()
	exp.From = from
	return exp
}

// TestOpenBoundRejectsNonceReplay pins the SDKP-001 nonce replay check
// (OpenBound step 7): the first open of a (from, nonce) pair is accepted
// and reserves the pair under wire.ScopeNonce, while a second open of the
// same pair is rejected as a replay with nil data.
func TestOpenBoundRejectsNonceReplay(t *testing.T) {
	recipient := newRecipient(t)
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	cache := newRecordingReplayCache()

	compact := sealBoundNonce(t, recipient, "party-seller", "replay-nonce-0123456789", now)

	data, err := OpenBound(context.Background(), compact, recipient, boundExpectations(), cache, clock)
	require.NoError(t, err, "the first open of a nonce must be accepted")
	assert.Equal(t, pepperShapedPayload(), data,
		"an accepted wrapper must return its payload bytes")

	data, err = OpenBound(context.Background(), compact, recipient, boundExpectations(), cache, clock)
	assert.Error(t, err, "a second open of the same (from, nonce) must be rejected as a replay")
	assert.Nil(t, data, "a replayed wrapper must return nil data")
	assert.ErrorContains(t, err, "replay", "the rejection must be reported as a replay")

	assert.Equal(t, wire.ScopeNonce, cache.lastCall(t).scope,
		"the nonce must be reserved under wire.ScopeNonce")
}

// TestOpenBoundSameNonceDifferentSenderAccepted pins the keying of the
// nonce replay check: the reservation is keyed by (from, nonce), so the
// same nonce arriving from a different sender is fresh and accepted, and
// only the original sender's pair is deduped.
func TestOpenBoundSameNonceDifferentSenderAccepted(t *testing.T) {
	recipient := newRecipient(t)
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	cache := newRecordingReplayCache()
	const nonce = "shared-nonce-0123456789"

	first := sealBoundNonce(t, recipient, "party-seller", nonce, now)
	second := sealBoundNonce(t, recipient, "party-other", nonce, now)

	data, err := OpenBound(context.Background(), first, recipient, boundExpectationsFrom("party-seller"), cache, clock)
	require.NoError(t, err, "the first sender's open must be accepted")
	assert.Equal(t, pepperShapedPayload(), data,
		"an accepted wrapper must return its payload bytes")

	data, err = OpenBound(context.Background(), second, recipient, boundExpectationsFrom("party-other"), cache, clock)
	require.NoError(t, err, "the same nonce from a different sender must be accepted")
	assert.Equal(t, pepperShapedPayload(), data,
		"an accepted wrapper must return its payload bytes")

	_, err = OpenBound(context.Background(), first, recipient, boundExpectationsFrom("party-seller"), cache, clock)
	assert.Error(t, err, "the original sender's pair must still dedupe after the other sender's open")
}

// TestOpenBoundNonceReplayReservationWindow pins how long the nonce
// reservation lasts: until at least now + 10 minutes with the default
// MaxAge, and until at least now + MaxAge + 60 s with MaxAge 15 minutes,
// measured against the frozen clock the open was given.
func TestOpenBoundNonceReplayReservationWindow(t *testing.T) {
	recipient := newRecipient(t)
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	cases := []struct {
		name      string
		maxAge    time.Duration
		wantUntil time.Time
	}{
		{name: "default MaxAge reserves at least 10 minutes", maxAge: 0, wantUntil: now.Add(10 * time.Minute)},
		{name: "MaxAge 15m reserves at least MaxAge plus 60s", maxAge: 15 * time.Minute, wantUntil: now.Add(15*time.Minute + 60*time.Second)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache := newRecordingReplayCache()
			compact := sealBoundNonce(t, recipient, "party-seller", "window-nonce-"+tc.name, now)
			exp := boundExpectations()
			exp.MaxAge = tc.maxAge

			data, err := OpenBound(context.Background(), compact, recipient, exp, cache, clock)
			require.NoError(t, err, "the first open must be accepted")
			assert.Equal(t, pepperShapedPayload(), data,
				"an accepted wrapper must return its payload bytes")

			call := cache.lastCall(t)
			assert.False(t, call.until.Before(tc.wantUntil),
				"the reservation must last until at least %s, got %s", tc.wantUntil, call.until)
		})
	}
}
