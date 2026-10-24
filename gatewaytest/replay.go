package gatewaytest

import "sync"

// Replay cache scopes: the two key spaces a ReplayCache keeps apart so a
// webhook_id never collides with a jti.
const (
	// ReplayScopeJTI scopes a cache entry to a token jti.
	ReplayScopeJTI = "jti"
	// ReplayScopeWebhookID scopes a cache entry to a webhook_id.
	ReplayScopeWebhookID = "webhook_id"
)

// ReplayCache is a deterministic in-memory replay cache for offline tests.
// It records (scope, key) pairs — a jti or a webhook_id — and reports the
// same verdict for the same key on every call after the first. It is safe
// for concurrent use.
type ReplayCache struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

// NewReplayCache returns an empty, concurrency-safe ReplayCache with no
// entries, no expiry, and no clock dependency.
//
// Returns: a ready-to-use *ReplayCache.
func NewReplayCache() *ReplayCache {
	return &ReplayCache{seen: make(map[string]struct{})}
}

// Check atomically records the (scope, key) pair and returns the verdict:
// true when the pair is observed for the first time (accepted), false on
// every later observation of the same pair (replay). The verdict depends
// only on the keys seen before the call — never on wall-clock time — so
// the same key always yields the same verdict.
//
// Parameters: scope — the key space (ReplayScopeJTI or ReplayScopeWebhookID);
// key — the jti or webhook_id value.
// Returns: true if accepted as fresh, false if it is a replay.
func (c *ReplayCache) Check(scope, key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := scope + "\x00" + key
	if _, dup := c.seen[k]; dup {
		return false
	}
	c.seen[k] = struct{}{}
	return true
}
