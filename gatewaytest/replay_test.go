package gatewaytest

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReplayCacheFirstAcceptedThenReplay asserts that the first Check of a
// (scope, key) pair is accepted and every later Check of the same pair is a
// replay, with the verdict unchanged across repeated calls.
func TestReplayCacheFirstAcceptedThenReplay(t *testing.T) {
	c := NewReplayCache()
	require.NotNil(t, c, "a new ReplayCache must be ready to use")

	const key = "replay-key-0001"
	assert.True(t, c.Check(ReplayScopeJTI, key),
		"the first Check of a key must be accepted")
	assert.False(t, c.Check(ReplayScopeJTI, key),
		"the second Check of the same key must be a replay")
	for i := 0; i < 5; i++ {
		assert.False(t, c.Check(ReplayScopeJTI, key),
			"the verdict must not change across repeated calls with the same key")
	}
}

// TestReplayCacheScopesAreIndependent asserts that the jti and webhook_id
// scopes are separate key spaces: the same raw key in a different scope is
// a distinct entry, so a webhook_id never collides with a jti.
func TestReplayCacheScopesAreIndependent(t *testing.T) {
	c := NewReplayCache()

	const key = "shared-key-material"
	assert.True(t, c.Check(ReplayScopeJTI, key), "fresh jti must be accepted")
	assert.True(t, c.Check(ReplayScopeWebhookID, key),
		"the same key under the webhook_id scope is a distinct entry")
	assert.False(t, c.Check(ReplayScopeWebhookID, key),
		"the webhook_id entry must now be a replay")
	assert.False(t, c.Check(ReplayScopeJTI, key),
		"the jti entry must still be a replay")
}

// TestReplayCacheDeterministicWithoutClock asserts the verdict depends only
// on the history of Check calls, never on wall-clock time: two caches driven
// by the same sequence of calls yield identical verdicts.
func TestReplayCacheDeterministicWithoutClock(t *testing.T) {
	sequence := []struct {
		scope string
		key   string
	}{
		{ReplayScopeJTI, "jti-alpha"},
		{ReplayScopeWebhookID, "whid-alpha"},
		{ReplayScopeJTI, "jti-alpha"},
		{ReplayScopeWebhookID, "whid-alpha"},
		{ReplayScopeJTI, "jti-beta"},
		{ReplayScopeJTI, "jti-beta"},
	}
	run := func() []bool {
		c := NewReplayCache()
		verdicts := make([]bool, 0, len(sequence))
		for _, s := range sequence {
			verdicts = append(verdicts, c.Check(s.scope, s.key))
		}
		return verdicts
	}
	assert.Equal(t, []bool{true, true, false, false, true, false}, run(),
		"first observation accepted, every repeat a replay")
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
			results[idx] = c.Check(ReplayScopeJTI, "concurrent-key")
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
