package envelope

import (
	"context"
	"crypto/ecdh"
	"fmt"
	"sync"
	"time"
)

// FetchFunc fetches a party's JWKS document as served by
// GET /v1/parties/{id}/jwks. It is supplied by the caller: the SDK never
// invents endpoints or keys.
//
// Parameters: ctx carries caller cancellation; partyID is the recipient
// party whose document to fetch.
// Returns: the raw JWKS document, or an error.
type FetchFunc func(ctx context.Context, partyID string) ([]byte, error)

// EncKeyResolver is the per-party cache of recipient use:enc keys behind
// SDKP-002: Resolve serves the selected key from cache for the whole TTL
// and fetches only when the entry is missing or stale; Refresh forces one
// refetch after a seal/open failure, rate-limited to at most one attempt
// per TTL window so repeated Refresh never loops. Any failure — a fetch
// error or a document without exactly one use:enc key — fails closed with a
// nil key and invalidates the cached entry, so a stale key is never served
// after a failure. Selection always goes through SelectRecipientEncKey
// (single use:enc key or deny). Safe for concurrent use: every lookup
// serializes on one mutex, so concurrent misses never stampede the fetch.
type EncKeyResolver struct {
	mu      sync.Mutex
	fetch   FetchFunc
	ttl     time.Duration
	clock   func() time.Time
	parties map[string]*resolverEntry
}

// resolverEntry holds one party's selected key and fetch timestamps.
type resolverEntry struct {
	pub     *ecdh.PublicKey
	kid     string
	fetched time.Time // last successful fetch, drives the TTL
	refresh time.Time // last Refresh attempt (success or failure), drives the rate limit
	haveKey bool
}

// NewEncKeyResolver returns a resolver that fetches party JWKS documents
// through fetch, serves each selected key for ttl, and reads the current
// time from clock (nil means time.Now — tests inject a deterministic clock
// so TTL and rate-limit expiry are reproducible). The ttl doubles as the
// Refresh rate-limit window: at most one forced refetch per ttl per party.
// A nil fetch makes every Resolve and Refresh fail closed with an error
// rather than panic; a non-positive ttl disables caching.
//
// Parameters: fetch retrieves a party's JWKS; ttl bounds caching and the
// Refresh window; clock reads the current time.
// Returns: a ready-to-use *EncKeyResolver.
func NewEncKeyResolver(fetch FetchFunc, ttl time.Duration, clock func() time.Time) *EncKeyResolver {
	if clock == nil {
		clock = time.Now
	}
	return &EncKeyResolver{
		fetch:   fetch,
		ttl:     ttl,
		clock:   clock,
		parties: make(map[string]*resolverEntry),
	}
}

// Resolve returns the party's current use:enc key and kid: the cached entry
// while it is younger than the TTL (no fetch call), otherwise one fetch
// followed by SelectRecipientEncKey over the fetched document.
//
// Parameters: ctx carries caller cancellation into any fetch; partyID is
// the recipient party.
// Returns: the recipient's X25519 public key, its kid, and nil, or an error
// with a nil key and an empty kid — a fetch error or a JWKS without exactly
// one use:enc key fails closed. Never panics.
func (r *EncKeyResolver) Resolve(ctx context.Context, partyID string) (*ecdh.PublicKey, string, error) {
	if r == nil || r.fetch == nil {
		return nil, "", fmt.Errorf("envelope: EncKeyResolver: no fetch function")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.entryLocked(partyID)
	if e.haveKey && r.clock().Sub(e.fetched) < r.ttl {
		return e.pub, e.kid, nil
	}
	return r.fetchKeyLocked(ctx, partyID, e)
}

// Refresh forces one refetch after a seal/open failure, even while the
// cached key is still inside its TTL, so a rotated recipient key is picked
// up without waiting. At most one Refresh attempt runs per ttl window per
// party: a second Refresh inside the window never fetches again (it serves
// the cached key, or fails closed when nothing is cached), so repeated
// Refresh after a failure never loops into a refetch storm.
//
// Parameters: ctx carries caller cancellation into the fetch; partyID is
// the recipient party.
// Returns: the recipient's X25519 public key, its kid, and nil, or an error
// with a nil key and an empty kid. Never panics.
func (r *EncKeyResolver) Refresh(ctx context.Context, partyID string) (*ecdh.PublicKey, string, error) {
	if r == nil || r.fetch == nil {
		return nil, "", fmt.Errorf("envelope: EncKeyResolver: no fetch function")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.entryLocked(partyID)
	now := r.clock()
	if !e.refresh.IsZero() && now.Sub(e.refresh) < r.ttl {
		// Rate-limited: no fetch. Any key on record was fetched no later
		// than this window's last attempt, so it is younger than the TTL.
		if e.haveKey {
			return e.pub, e.kid, nil
		}
		return nil, "", fmt.Errorf("envelope: EncKeyResolver: party %q: refresh rate-limited, no cached key", partyID)
	}
	e.refresh = now
	return r.fetchKeyLocked(ctx, partyID, e)
}

// entryLocked returns the party's cache entry, creating it on first use.
// Callers hold r.mu.
func (r *EncKeyResolver) entryLocked(partyID string) *resolverEntry {
	e, ok := r.parties[partyID]
	if !ok {
		e = &resolverEntry{}
		r.parties[partyID] = e
	}
	return e
}

// fetchKeyLocked calls fetch exactly once and installs the selected key on
// success. Any failure — a fetch error or a document that fails the
// fail-closed SelectRecipientEncKey selection — clears the cached key and
// returns a nil key, so a stale key is never served after a failure.
// Callers hold r.mu.
func (r *EncKeyResolver) fetchKeyLocked(ctx context.Context, partyID string, e *resolverEntry) (*ecdh.PublicKey, string, error) {
	doc, err := r.fetch(ctx, partyID)
	if err != nil {
		e.pub, e.kid, e.haveKey = nil, "", false
		return nil, "", fmt.Errorf("envelope: EncKeyResolver: party %q: fetch JWKS: %w", partyID, err)
	}
	pub, kid, err := SelectRecipientEncKey(doc)
	if err != nil {
		e.pub, e.kid, e.haveKey = nil, "", false
		return nil, "", fmt.Errorf("envelope: EncKeyResolver: party %q: %w", partyID, err)
	}
	e.pub, e.kid, e.fetched, e.haveKey = pub, kid, r.clock(), true
	return pub, kid, nil
}
