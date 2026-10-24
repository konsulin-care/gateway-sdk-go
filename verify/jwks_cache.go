package verify

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
)

// maxJWKSBytes caps how much of a JWKS response the cache reads: a legitimate
// gateway set is a handful of keys, so anything larger is refused fail-closed
// instead of buffered.
const maxJWKSBytes = 1 << 20 // 1 MiB

// jwksCache is the gateway JWKS cache behind SDK-VERIFY-001: the document is
// fetched at most once per TTL, keys are selected by the token's own header
// kid only (jwk.KeySet.SigByKid — never by alg or use, never from anywhere
// but the JWKS), an unknown kid triggers at most one refetch per global
// rate-limit window and then denies with ErrUnknownKid, and a failed fetch
// keeps the last good set. Safe for concurrent use: every lookup serializes
// on one mutex, so concurrent misses never stampede the endpoint.
type jwksCache struct {
	mu              sync.Mutex
	url             string
	client          *http.Client
	ttl             time.Duration
	refetchInterval time.Duration
	clock           func() time.Time

	set        jwk.KeySet
	haveSet    bool
	fetched    time.Time
	refetched  time.Time
	didRefetch bool
}

// newJWKSCache returns a cache that fetches jwksURL through client. ttl is
// how long a fetched document is served before a refresh; refetchInterval is
// the global rate-limit window inside which at most one unknown-kid refetch
// runs; clock reads the current time (nil means time.Now — tests inject a
// deterministic clock so TTL and window expiry are reproducible). A nil
// client means http.DefaultClient.
//
// Parameters: jwksURL is the gateway JWKS endpoint; client fetches it; ttl
// and refetchInterval bound fetching; clock reads the current time.
// Returns: a ready-to-use *jwksCache.
func newJWKSCache(jwksURL string, client *http.Client, ttl, refetchInterval time.Duration, clock func() time.Time) *jwksCache {
	if client == nil {
		client = http.DefaultClient
	}
	if clock == nil {
		clock = time.Now
	}
	return &jwksCache{
		url:             jwksURL,
		client:          client,
		ttl:             ttl,
		refetchInterval: refetchInterval,
		clock:           clock,
	}
}

// signingKey resolves kid against the cached gateway JWKS and returns the
// Ed25519 public key a token's signature must verify under. Selection is
// kid-only: an unknown kid, an empty kid, or a kid that only matches a
// non-signing entry (an X25519 use:enc key) denies with ErrUnknownKid, so an
// encryption key is never usable for signatures. A miss on an empty or
// TTL-expired cache fetches the document once; a miss on a fresh cache
// triggers one refetch per global rate-limit window (refetchInterval), and
// every later unknown kid inside the window denies without a fetch. A failed
// fetch keeps the last good set.
//
// Parameters: ctx carries caller cancellation into any fetch; kid is the
// token's own header kid (never a caller hint).
// Returns: the Ed25519 public key and nil, or an error. ErrUnknownKid
// (errors.Is) covers every unknown or non-signing kid; a fetch error denies
// only when no usable set exists. Fail closed; never panics.
func (c *jwksCache) signingKey(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	if kid == "" {
		return nil, fmt.Errorf("verify: jwks: %w: empty kid", ErrUnknownKid)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	fetched, err := c.ensureFetchedLocked(ctx)
	if err != nil {
		return nil, fmt.Errorf("verify: jwks: fetch %s: %w", c.url, err)
	}
	if key, ok := c.set.SigByKid(kid); ok {
		return ed25519SigningKey(key)
	}
	if fetched {
		// The set was just fetched and still lacks the kid as a signing
		// key; another fetch in the same lookup would only stampede.
		return nil, fmt.Errorf("verify: jwks: %w: kid %q", ErrUnknownKid, kid)
	}
	if c.hasKid(kid) {
		// The kid is served but is not a signing key (an X25519 use:enc
		// entry): a refetch can never turn it into one, so deny without
		// touching the network or spending the refetch window.
		return nil, fmt.Errorf("verify: jwks: %w: kid %q is not a signing key", ErrUnknownKid, kid)
	}
	now := c.clock()
	if c.didRefetch && now.Sub(c.refetched) < c.refetchInterval {
		return nil, fmt.Errorf("verify: jwks: %w: kid %q", ErrUnknownKid, kid)
	}
	c.didRefetch, c.refetched = true, now
	if err := c.fetchLocked(ctx); err == nil {
		if key, ok := c.set.SigByKid(kid); ok {
			return ed25519SigningKey(key)
		}
	}
	return nil, fmt.Errorf("verify: jwks: %w: kid %q", ErrUnknownKid, kid)
}

// ensureFetchedLocked fetches the document when the cache is empty (first
// lookup) or stale (now - fetched >= ttl), and reports whether a fetch was
// attempted this lookup. A bootstrap failure (no set yet) returns the fetch
// error — nothing can verify without a first good set. A failed refresh
// keeps the last good set: its keys keep verifying, and the fetch time is
// advanced one TTL so a down endpoint is not hammered. Callers hold c.mu.
func (c *jwksCache) ensureFetchedLocked(ctx context.Context) (bool, error) {
	now := c.clock()
	switch {
	case !c.haveSet:
		if err := c.fetchLocked(ctx); err != nil {
			return true, err
		}
		return true, nil
	case now.Sub(c.fetched) >= c.ttl:
		if err := c.fetchLocked(ctx); err != nil {
			c.fetched = now
		}
		return true, nil
	default:
		return false, nil
	}
}

// fetchLocked GETs the JWKS URL and replaces the cached set with the parsed
// document, recording the fetch time. Any failure — transport, non-200
// status, oversized or unreadable body, or a document that fails the
// fail-closed jwk parser — leaves the previous set untouched. Callers hold
// c.mu.
func (c *jwksCache) fetchLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return fmt.Errorf("document exceeds %d bytes", maxJWKSBytes)
	}
	set, err := jwk.ParseJWKS(body)
	if err != nil {
		return err
	}
	c.set = set
	c.haveSet = true
	c.fetched = c.clock()
	return nil
}

// hasKid reports whether any key in the cached set carries kid, whatever its
// kind — the "present but not a signing key" test. Callers hold c.mu.
func (c *jwksCache) hasKid(kid string) bool {
	for _, key := range c.set.Keys {
		if key.Kid == kid {
			return true
		}
	}
	return false
}

// ed25519SigningKey decodes a selected signing JWK to its raw Ed25519 public
// key. A signing key of another type (EC/P-256) is denied: this verifier is
// EdDSA-only, so an ES256 key never verifies a gateway token here.
//
// Parameters: key is the JWK selected by SigByKid.
// Returns: the 32-byte Ed25519 public key and nil, or an error naming the
// rejection. Fail closed; never panics.
func ed25519SigningKey(key jwk.Key) (ed25519.PublicKey, error) {
	if key.Kty != "OKP" || key.Crv != "Ed25519" {
		return nil, fmt.Errorf("verify: jwks: kid %q: key type %s/%s is not Ed25519",
			key.Kid, key.Kty, key.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("verify: jwks: kid %q: key x: %w", key.Kid, err)
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("verify: jwks: kid %q: key x is %d bytes, want %d",
			key.Kid, len(x), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(x), nil
}
