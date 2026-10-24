package gatewaytest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/verify"
)

// Compile-time assertion: the fake cache satisfies the verify.ReplayCache
// interface. It lives in this test file so non-test gatewaytest never
// imports verify (which would risk cycles with verify's own tests).
var _ verify.ReplayCache = (*ReplayCache)(nil)

// verdict runs one Check of the fake cache with a realistic until and
// returns its accept/replay verdict, failing the test on any error. The
// fake never errors.
func verdict(t *testing.T, c *ReplayCache, scope, key string) bool {
	t.Helper()
	ok, err := c.Check(context.Background(), scope, key, time.Now().Add(24*time.Hour))
	require.NoError(t, err, "the deterministic replay cache must never error")
	return ok
}

// TestReplayCacheFirstAcceptedThenReplay asserts that the first Check of a
// (scope, key) pair is accepted and every later Check of the same pair is a
// replay, with the verdict unchanged across repeated calls.
func TestReplayCacheFirstAcceptedThenReplay(t *testing.T) {
	c := NewReplayCache()
	require.NotNil(t, c, "a new ReplayCache must be ready to use")

	const key = "replay-key-0001"
	assert.True(t, verdict(t, c, ReplayScopeJTI, key),
		"the first Check of a key must be accepted")
	assert.False(t, verdict(t, c, ReplayScopeJTI, key),
		"the second Check of the same key must be a replay")
	for i := 0; i < 5; i++ {
		assert.False(t, verdict(t, c, ReplayScopeJTI, key),
			"the verdict must not change across repeated calls with the same key")
	}
}

// TestReplayCacheScopesAreIndependent asserts that the jti and webhook_id
// scopes are separate key spaces: the same raw key in a different scope is
// a distinct entry, so a webhook_id never collides with a jti.
func TestReplayCacheScopesAreIndependent(t *testing.T) {
	c := NewReplayCache()

	const key = "shared-key-material"
	assert.True(t, verdict(t, c, ReplayScopeJTI, key), "fresh jti must be accepted")
	assert.True(t, verdict(t, c, ReplayScopeWebhookID, key),
		"the same key under the webhook_id scope is a distinct entry")
	assert.False(t, verdict(t, c, ReplayScopeWebhookID, key),
		"the webhook_id entry must now be a replay")
	assert.False(t, verdict(t, c, ReplayScopeJTI, key),
		"the jti entry must still be a replay")
}

// TestReplayCacheReleaseDeletesTheEntry asserts Release frees the (scope,
// key) entry so the key is fresh again on the next Check — the retry path a
// handler failure (5xx or panic) takes — and that Release scopes to the
// named key space only.
func TestReplayCacheReleaseDeletesTheEntry(t *testing.T) {
	c := NewReplayCache()
	ctx := context.Background()
	const key = "released-key"

	require.True(t, verdict(t, c, ReplayScopeJTI, key))
	require.False(t, verdict(t, c, ReplayScopeJTI, key))
	require.True(t, verdict(t, c, ReplayScopeWebhookID, key),
		"also reserve the same raw key in the webhook_id scope")
	require.False(t, verdict(t, c, ReplayScopeWebhookID, key))

	require.NoError(t, c.Release(ctx, ReplayScopeJTI, key), "Release must succeed")
	assert.True(t, verdict(t, c, ReplayScopeJTI, key),
		"after Release the key must be fresh again")
	assert.False(t, verdict(t, c, ReplayScopeWebhookID, key),
		"the webhook_id entry (seen via the same raw key) must be untouched")

	assert.NoError(t, c.Release(ctx, ReplayScopeJTI, "never-seen"),
		"releasing an unreserved pair must be a no-op, not an error")
}

// TestReplayCacheDeterministicWithoutClock asserts the verdict depends only
// on the history of Check calls, never on wall-clock time and never on the
// until argument: two caches driven by the same sequence of calls — with
// wildly different until values — yield identical verdicts.
func TestReplayCacheDeterministicWithoutClock(t *testing.T) {
	sequence := []struct {
		scope string
		key   string
		until time.Time
	}{
		{ReplayScopeJTI, "jti-alpha", time.Unix(1, 0)},
		{ReplayScopeWebhookID, "whid-alpha", time.Now().Add(100 * time.Hour)},
		{ReplayScopeJTI, "jti-alpha", time.Unix(1_700_000_000, 0)},
		{ReplayScopeWebhookID, "whid-alpha", time.Time{}},
		{ReplayScopeJTI, "jti-beta", time.Now()},
		{ReplayScopeJTI, "jti-beta", time.Now().Add(-time.Hour)},
	}
	run := func() []bool {
		c := NewReplayCache()
		verdicts := make([]bool, 0, len(sequence))
		for _, s := range sequence {
			ok, err := c.Check(context.Background(), s.scope, s.key, s.until)
			require.NoError(t, err)
			verdicts = append(verdicts, ok)
		}
		return verdicts
	}
	assert.Equal(t, []bool{true, true, false, false, true, false}, run(),
		"first observation accepted, every repeat a replay, regardless of until")
	assert.Equal(t, run(), run(),
		"verdicts must be identical across independent runs: no clock input")
}

// TestReplayCacheConcurrentSingleWinner asserts that lookup-and-insert is
// atomic per key under concurrent use: of many simultaneous Checks of one
// key exactly one is accepted.
func TestReplayCacheConcurrentSingleWinner(t *testing.T) {
	c := NewReplayCache()
	const n = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			ok, err := c.Check(context.Background(), ReplayScopeJTI, "concurrent-key", time.Time{})
			if err != nil {
				t.Errorf("Check: %v", err)
				return
			}
			results[idx] = ok
		}(i)
	}
	close(start)
	wg.Wait()

	accepted := 0
	for _, r := range results {
		if r {
			accepted++
		}
	}
	assert.Equal(t, 1, accepted,
		"exactly one concurrent Check of the same key must be accepted")
}
