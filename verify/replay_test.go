package verify_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/verify"
)

// Compile-time assertion: the in-memory default satisfies the interface
// every caller (middleware, Ticket) programs against.
var _ verify.ReplayCache = (*verify.MemoryReplayCache)(nil)

// newFakeClock returns a deterministic clock reading a fixed instant plus a
// function advancing it — the injected clock the expiry tests drive.
func newFakeClock(start time.Time) (func() time.Time, func(time.Duration)) {
	var mu sync.Mutex
	now := start
	return func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}, func(d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			now = now.Add(d)
		}
}

// verdict runs one Check with no error expected and returns the accept /
// replay verdict. The in-memory cache never errors.
func verdict(t *testing.T, c verify.ReplayCache, scope, key string, until time.Time) bool {
	t.Helper()
	ok, err := c.Check(context.Background(), scope, key, until)
	require.NoError(t, err, "the in-memory replay cache must never error")
	return ok
}

// TestMemoryReplayCacheFirstAcceptedThenReplay asserts the atomic
// reserve-on-check contract: the first Check of a (scope, key) pair is
// accepted and every later Check of the same live pair is a replay.
func TestMemoryReplayCacheFirstAcceptedThenReplay(t *testing.T) {
	c := verify.NewMemoryReplayCache(nil)
	const key = "replay-key-0001"
	until := time.Now().Add(time.Hour)

	assert.True(t, verdict(t, c, verify.ScopeJTI, key, until),
		"the first Check of a key must be accepted")
	assert.False(t, verdict(t, c, verify.ScopeJTI, key, until),
		"the second Check of the same key must be a replay")
	for i := 0; i < 5; i++ {
		assert.False(t, verdict(t, c, verify.ScopeJTI, key, until),
			"the verdict must not change across repeated Checks of the same key")
	}
}

// TestMemoryReplayCacheScopesAreIndependent asserts the jti and webhook_id
// scopes are separate key spaces: the same raw key under a different scope is
// a distinct reservation, so a webhook_id never collides with a jti.
func TestMemoryReplayCacheScopesAreIndependent(t *testing.T) {
	c := verify.NewMemoryReplayCache(nil)
	const key = "shared-key-material"
	until := time.Now().Add(time.Hour)

	assert.True(t, verdict(t, c, verify.ScopeJTI, key, until),
		"fresh jti must be accepted")
	assert.True(t, verdict(t, c, verify.ScopeWebhookID, key, until),
		"the same key under the webhook_id scope is a distinct reservation")
	assert.False(t, verdict(t, c, verify.ScopeWebhookID, key, until),
		"the webhook_id entry must now be a replay")
	assert.False(t, verdict(t, c, verify.ScopeJTI, key, until),
		"the jti entry must still be a replay")
}

// TestMemoryReplayCacheExpiresAfterUntil asserts a reservation stops applying
// once its until passes under the injected clock: the key becomes fresh
// again and can be re-reserved.
func TestMemoryReplayCacheExpiresAfterUntil(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock, advance := newFakeClock(now)
	c := verify.NewMemoryReplayCache(clock)

	const key = "expiring-key"
	until := now.Add(time.Minute)
	assert.True(t, verdict(t, c, verify.ScopeJTI, key, until),
		"the first Check must reserve the key")
	assert.False(t, verdict(t, c, verify.ScopeJTI, key, until),
		"the key is a replay until its until passes")

	advance(59 * time.Second)
	assert.False(t, verdict(t, c, verify.ScopeJTI, key, until),
		"one second before until the reservation still holds")

	advance(2 * time.Second)
	assert.True(t, verdict(t, c, verify.ScopeJTI, key, until.Add(2*time.Minute)),
		"once until passes the key must be fresh again")
	assert.False(t, verdict(t, c, verify.ScopeJTI, key, until.Add(2*time.Minute)),
		"the re-reserved key is a replay again")
}

// TestMemoryReplayCacheReleaseMakesKeyFresh asserts Release frees the
// reservation so the same key is accepted on the next Check — the path a
// handler failure (5xx or panic) takes to let a legitimate retry through.
func TestMemoryReplayCacheReleaseMakesKeyFresh(t *testing.T) {
	c := verify.NewMemoryReplayCache(nil)
	ctx := context.Background()
	const key = "released-key"
	until := time.Now().Add(time.Hour)

	require.True(t, verdict(t, c, verify.ScopeJTI, key, until))
	require.False(t, verdict(t, c, verify.ScopeJTI, key, until))

	require.NoError(t, c.Release(ctx, verify.ScopeJTI, key),
		"Release must succeed")
	assert.True(t, verdict(t, c, verify.ScopeJTI, key, until),
		"after Release the key must be fresh again")

	assert.NoError(t, c.Release(ctx, verify.ScopeJTI, "never-seen"),
		"releasing an unreserved pair must be a no-op, not an error")
}

// TestMemoryReplayCacheReleaseIsScoped asserts Release only frees the
// reservation in the named scope: the other scope's entry is untouched.
func TestMemoryReplayCacheReleaseIsScoped(t *testing.T) {
	c := verify.NewMemoryReplayCache(nil)
	const key = "scoped-release"
	until := time.Now().Add(time.Hour)

	require.True(t, verdict(t, c, verify.ScopeJTI, key, until))
	require.True(t, verdict(t, c, verify.ScopeWebhookID, key, until))

	require.NoError(t, c.Release(context.Background(), verify.ScopeJTI, key))
	assert.True(t, verdict(t, c, verify.ScopeJTI, key, until),
		"the jti reservation was released, so it is fresh")
	assert.False(t, verdict(t, c, verify.ScopeWebhookID, key, until),
		"the webhook_id reservation must be untouched by a jti Release")
}

// TestMemoryReplayCacheConcurrentSingleWinner asserts lookup-and-reserve is
// atomic per key under concurrent use: of many simultaneous Checks of one
// key exactly one is accepted.
func TestMemoryReplayCacheConcurrentSingleWinner(t *testing.T) {
	c := verify.NewMemoryReplayCache(nil)
	const n = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			ok, err := c.Check(context.Background(), verify.ScopeJTI,
				"concurrent-key", time.Now().Add(time.Hour))
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
