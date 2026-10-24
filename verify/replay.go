package verify

import (
	"context"
	"sync"
	"time"
)

// Replay cache scopes: the two key spaces a ReplayCache keeps apart so a
// webhook_id never collides with a jti.
const (
	// ScopeJTI scopes a replay-cache entry to a token jti.
	ScopeJTI = "jti"
	// ScopeWebhookID scopes a replay-cache entry to a webhook_id.
	ScopeWebhookID = "webhook_id"
)

// sweepInterval is the number of Check reservations between full expiry
// sweeps of a MemoryReplayCache map; expired entries are always dropped
// eagerly on their own key, the sweep only bounds memory for keys never
// checked again.
const sweepInterval = 1024

// ReplayCache atomically deduplicates inbound gateway tokens (SDK-VERIFY-003,
// SDK-VERIFY-004). Check reserves the (scope, key) pair until the until
// instant: the first Check of a fresh pair is accepted, every later Check of
// the same live pair is a replay. Any error denies — a cache that cannot
// record must not let a token through. Release frees a reservation so a
// retry after a failed handler (5xx or panic) is not deduped.
//
// Implementations must be safe for concurrent use. The in-process default is
// MemoryReplayCache; multi-instance callers plug their own (e.g. Redis).
type ReplayCache interface {
	// Check atomically reserves the (scope, key) pair until until.
	//
	// Parameters: ctx carries caller cancellation; scope is ScopeJTI or
	// ScopeWebhookID; key is the jti or webhook_id value; until is the
	// instant after which the reservation no longer applies.
	// Returns: true when the pair is fresh (accepted), false when it is a
	// replay, or an error — callers deny on error.
	Check(ctx context.Context, scope, key string, until time.Time) (bool, error)

	// Release frees the (scope, key) reservation, making the key fresh
	// again. Releasing an unreserved pair is a no-op.
	//
	// Parameters: ctx carries caller cancellation; scope is ScopeJTI or
	// ScopeWebhookID; key is the jti or webhook_id value.
	// Returns: nil on success or an error.
	Release(ctx context.Context, scope, key string) error
}

// MemoryReplayCache is the in-process ReplayCache default: a mutex-guarded
// map of (scope, key) pairs to their reservation deadline. It is safe for
// concurrent use, stops honouring an entry once its until passes under the
// injected clock (dropped lazily on access and by an amortized sweep), and
// never returns an error.
type MemoryReplayCache struct {
	mu      sync.Mutex
	clock   func() time.Time
	seen    map[string]time.Time
	inserts int
}

// NewMemoryReplayCache returns an empty, concurrency-safe ReplayCache over a
// process-local map.
//
// Parameters: clock reads the current time — pass nil for time.Now, or an
// injected deterministic clock in tests so entry expiry is reproducible.
// Returns: a ready-to-use *MemoryReplayCache.
func NewMemoryReplayCache(clock func() time.Time) *MemoryReplayCache {
	if clock == nil {
		clock = time.Now
	}
	return &MemoryReplayCache{
		clock: clock,
		seen:  make(map[string]time.Time),
	}
}

// Check atomically reserves (scope, key) until until: true when the pair is
// fresh — never seen or last reserved before until — false while a live
// reservation for the same pair exists. It never errors and ignores the
// context; the operation is a single in-process map mutation.
//
// Parameters: ctx is ignored (in-process map); scope is ScopeJTI or
// ScopeWebhookID; key is the jti or webhook_id value; until is the
// reservation deadline.
// Returns: true if accepted as fresh, false if it is a replay; nil error.
func (c *MemoryReplayCache) Check(_ context.Context, scope, key string, until time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	k := scope + "\x00" + key
	if exp, live := c.seen[k]; live && now.Before(exp) {
		return false, nil
	}
	c.seen[k] = until
	c.inserts++
	if c.inserts%sweepInterval == 0 {
		c.sweepLocked(now)
	}
	return true, nil
}

// Release frees the (scope, key) reservation so the key is fresh again; it
// never errors and ignores the context.
//
// Parameters: ctx is ignored (in-process map); scope is ScopeJTI or
// ScopeWebhookID; key is the jti or webhook_id value.
// Returns: nil always.
func (c *MemoryReplayCache) Release(_ context.Context, scope, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.seen, scope+"\x00"+key)
	return nil
}

// sweepLocked drops every reservation whose until has passed, bounding the
// map for keys never checked again. Callers hold c.mu.
func (c *MemoryReplayCache) sweepLocked(now time.Time) {
	for k, exp := range c.seen {
		if !now.Before(exp) {
			delete(c.seen, k)
		}
	}
}
