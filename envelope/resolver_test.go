package envelope

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolverClock is a deterministic clock: the resolver TTL and the Refresh
// rate-limit window are only testable against a fake.
type resolverClock struct {
	t time.Time
}

// newResolverClock returns a fake clock starting at a fixed instant.
func newResolverClock() *resolverClock {
	return &resolverClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
}

// tick advances the fake clock by d.
func (c *resolverClock) tick(d time.Duration) { c.t = c.t.Add(d) }

// read returns the current fake time, ready to pass as the resolver clock.
func (c *resolverClock) read() time.Time { return c.t }

// countingFetch serves doc (or err) and counts every call, recording the
// last party id requested.
type countingFetch struct {
	calls     int
	doc       []byte
	err       error
	lastParty string
}

// fn returns the FetchFunc under test.
func (f *countingFetch) fn() FetchFunc {
	return func(_ context.Context, partyID string) ([]byte, error) {
		f.calls++
		f.lastParty = partyID
		if f.err != nil {
			return nil, f.err
		}
		return f.doc, nil
	}
}

// TestEncKeyResolverResolveCachesWithinTTL asserts SDKP-002: Resolve fetches
// a party's JWKS once, serves the selected key from cache for the whole TTL
// without calling fetch, fetches again once the TTL expires, and keeps a
// separate entry per party id.
func TestEncKeyResolverResolveCachesWithinTTL(t *testing.T) {
	first := newRecipient(t)
	second := newRecipient(t)
	firstDoc := partyJWKS(t, first.PublicKey(), "enc-first")
	secondDoc := partyJWKS(t, second.PublicKey(), "enc-second")

	clock := newResolverClock()
	f := &countingFetch{doc: firstDoc}
	r := NewEncKeyResolver(f.fn(), 5*time.Minute, clock.read)

	pub, kid, err := r.Resolve(context.Background(), "party-1")
	require.NoError(t, err)
	require.NotNil(t, pub, "the first Resolve must fetch and select the use:enc key")
	assert.Equal(t, "enc-first", kid, "Resolve must return the selected kid")
	assert.Equal(t, 1, f.calls, "the first Resolve must fetch exactly once")
	assert.Equal(t, "party-1", f.lastParty, "fetch must receive the caller's party id")

	clock.tick(time.Minute)
	pub2, kid2, err := r.Resolve(context.Background(), "party-1")
	require.NoError(t, err)
	require.NotNil(t, pub2, "a cached Resolve must keep returning the key")
	assert.Equal(t, 1, f.calls,
		"within the TTL Resolve must serve the cache without calling fetch")
	assert.Equal(t, kid, kid2, "the cached Resolve must return the same kid")
	assert.True(t, pub2.Equal(first.PublicKey()),
		"the cached Resolve must return the same key")

	clock.tick(10 * time.Minute) // now well past the TTL
	_, _, err = r.Resolve(context.Background(), "party-1")
	require.NoError(t, err)
	assert.Equal(t, 2, f.calls,
		"after the TTL expires Resolve must fetch again")

	f.doc = secondDoc
	pub3, kid3, err := r.Resolve(context.Background(), "party-2")
	require.NoError(t, err)
	require.NotNil(t, pub3, "a new party must resolve its own key")
	assert.Equal(t, 3, f.calls, "an uncached party must fetch")
	assert.Equal(t, "enc-second", kid3,
		"each party id must get its own cached entry")
	assert.True(t, pub3.Equal(second.PublicKey()))

	pub4, kid4, err := r.Resolve(context.Background(), "party-1")
	require.NoError(t, err)
	require.NotNil(t, pub4)
	assert.Equal(t, 3, f.calls,
		"a second party's fetch must not invalidate the first party's cache")
	assert.Equal(t, "enc-first", kid4,
		"party-1 must keep its own cached key")
	assert.True(t, pub4.Equal(first.PublicKey()))
}

// TestEncKeyResolverRefreshForcesOneFetchRateLimited asserts SDKP-002:
// Refresh forces exactly one refetch even when the cached key is fresh (the
// seal/open just failed with it), a second Refresh inside the rate-limit
// interval does not fetch again, and the window reopens after it expires.
func TestEncKeyResolverRefreshForcesOneFetchRateLimited(t *testing.T) {
	recipient := newRecipient(t)
	doc := partyJWKS(t, recipient.PublicKey(), "recipient-enc")
	clock := newResolverClock()
	f := &countingFetch{doc: doc}
	r := NewEncKeyResolver(f.fn(), 5*time.Minute, clock.read)

	_, _, err := r.Resolve(context.Background(), "party-1")
	require.NoError(t, err)
	require.Equal(t, 1, f.calls, "the initial Resolve must fetch once")

	// A seal/open failure right after a fresh Resolve must still refetch.
	pub, kid, err := r.Refresh(context.Background(), "party-1")
	require.NoError(t, err)
	require.NotNil(t, pub, "Refresh must return the refetched key")
	assert.Equal(t, "recipient-enc", kid, "Refresh must return the selected kid")
	assert.Equal(t, 2, f.calls, "Refresh must trigger exactly one fetch")

	clock.tick(time.Minute)
	pub2, kid2, err := r.Refresh(context.Background(), "party-1")
	require.NoError(t, err)
	require.NotNil(t, pub2,
		"a rate-limited Refresh must still serve the cached key")
	assert.Equal(t, 2, f.calls,
		"a second Refresh within the rate-limit interval must not fetch again")
	assert.Equal(t, kid, kid2, "the rate-limited Refresh must serve the cached kid")

	clock.tick(10 * time.Minute)
	_, _, err = r.Refresh(context.Background(), "party-1")
	require.NoError(t, err)
	assert.Equal(t, 3, f.calls,
		"a Refresh after the rate-limit interval must fetch again")
}

// TestEncKeyResolverRefreshRateLimitsFailedFetches asserts SDKP-002: a
// failing fetch is rate-limited too — repeated Refresh after a failure never
// loops into a refetch storm, and every attempt fails closed.
func TestEncKeyResolverRefreshRateLimitsFailedFetches(t *testing.T) {
	clock := newResolverClock()
	f := &countingFetch{err: errors.New("gateway unreachable")}
	r := NewEncKeyResolver(f.fn(), 5*time.Minute, clock.read)

	_, _, err := r.Refresh(context.Background(), "party-1")
	require.Error(t, err, "a failed forced fetch must fail closed")
	assert.Equal(t, 1, f.calls, "the first Refresh must attempt one fetch")

	_, _, err = r.Refresh(context.Background(), "party-1")
	require.Error(t, err,
		"with nothing cached a rate-limited Refresh must fail closed")
	assert.Equal(t, 1, f.calls,
		"a repeated Refresh within the interval must not fetch again")
}

// TestEncKeyResolverResolveFailsClosed asserts SDKP-002: a fetch error or a
// JWKS without a use:enc key makes Resolve fail closed with a nil key and an
// empty kid — no key is ever selected without a good document.
func TestEncKeyResolverResolveFailsClosed(t *testing.T) {
	t.Run("fetch error", func(t *testing.T) {
		clock := newResolverClock()
		f := &countingFetch{err: errors.New("gateway unreachable")}
		r := NewEncKeyResolver(f.fn(), 5*time.Minute, clock.read)

		pub, kid, err := r.Resolve(context.Background(), "party-1")
		require.Error(t, err, "a fetch error must fail closed")
		assert.Nil(t, pub, "a failed Resolve must return no key")
		assert.Empty(t, kid, "a failed Resolve must return no kid")
		assert.Equal(t, 1, f.calls, "the failed Resolve must attempt one fetch")
	})

	t.Run("no use:enc key", func(t *testing.T) {
		sigOnly := jwksDoc(t, map[string]string{
			"alg": "EdDSA", "crv": "Ed25519", "kid": "sig-current", "kty": "OKP",
			"use": "sig", "x": "iRjI0Qr9WRzkvTcY4bv8tAGPgBGrj83PSikHxaRFKyM",
		})
		clock := newResolverClock()
		f := &countingFetch{doc: sigOnly}
		r := NewEncKeyResolver(f.fn(), 5*time.Minute, clock.read)

		pub, kid, err := r.Resolve(context.Background(), "party-1")
		require.Error(t, err,
			"a JWKS without a use:enc key must fail closed")
		assert.Nil(t, pub, "a failed selection must return no key")
		assert.Empty(t, kid, "a failed selection must return no kid")
	})
}
