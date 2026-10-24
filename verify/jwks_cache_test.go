package verify

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// jwksCacheTestTTL and jwksCacheTestWindow are the cache timings every test
// in this file injects; the clock is always fake so TTL and rate-limit window
// expiry are deterministic.
const (
	jwksCacheTestTTL    = 5 * time.Minute
	jwksCacheTestWindow = 30 * time.Second
)

// testSigner is one Ed25519 test key with its derived kid (RFC 7638
// thumbprint) — enough to mint tokens and build JWKS entries offline.
type testSigner struct {
	priv ed25519.PrivateKey
	kid  string
}

// newTestSigner generates a fresh Ed25519 key and derives its kid as the RFC
// 7638 thumbprint of the public key — exactly how the gateway names its keys.
func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.Public().(ed25519.PublicKey)
	raw, err := json.Marshal(map[string]string{
		"crv": "Ed25519",
		"kty": "OKP",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	})
	require.NoError(t, err)
	kid, err := jwk.Thumbprint(raw)
	require.NoError(t, err)
	return &testSigner{priv: priv, kid: kid}
}

// sigJWK returns the signer's public key as a sig JWK object, the kind of
// entry the gateway JWKS serves for its signing keys.
func (s *testSigner) sigJWK(t *testing.T) map[string]any {
	t.Helper()
	pub := s.priv.Public().(ed25519.PublicKey)
	return map[string]any{
		"alg": "EdDSA",
		"crv": "Ed25519",
		"kid": s.kid,
		"kty": "OKP",
		"use": "sig",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// mint signs an empty ks-delivery token with the signer's key and its own
// kid — a stand-in for any gateway-signed token (the cache stage runs before
// any claim checks).
func (s *testSigner) mint(t *testing.T) string {
	t.Helper()
	return s.mintAs(t, s.kid)
}

// mintAs signs an empty ks-delivery token with the signer's key under an
// arbitrary header kid — the way a mistaken or hostile sender stamps a kid
// the gateway does not sign with.
func (s *testSigner) mintAs(t *testing.T, kid string) string {
	t.Helper()
	tok, err := jws.SignEd25519(s.priv,
		jws.Header{Alg: jws.AlgEdDSA, Kid: kid, Typ: wire.TypDelivery}, []byte(`{}`))
	require.NoError(t, err)
	return tok
}

// jwksDoc builds one JWKS document from the given key objects and asserts it
// passes the fail-closed internal/jwk parser, so no test can accidentally
// serve a document the SDK would refuse to parse.
func jwksDoc(t *testing.T, keys ...any) []byte {
	t.Helper()
	doc, err := json.Marshal(map[string]any{"keys": keys})
	require.NoError(t, err)
	_, err = jwk.ParseJWKS(doc)
	require.NoError(t, err, "every test JWKS must pass the fail-closed parser")
	return doc
}

// encX25519JWK builds an X25519 use:enc recipient JWK with the given kid —
// the key kind that must never resolve as a signature key.
func encX25519JWK(t *testing.T, kid string) map[string]any {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return map[string]any{
		"alg": "ECDH-ES",
		"crv": "X25519",
		"kid": kid,
		"kty": "OKP",
		"use": "enc",
		"x":   base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}
}

// countingJWKSServer is a fake gateway JWKS endpoint that counts every fetch
// and serves a swappable document — the fetch counter these cache tests pin.
type countingJWKSServer struct {
	mu      sync.Mutex
	body    []byte
	failing bool
	fetches int
	server  *httptest.Server
}

// newCountingJWKSServer starts a local httptest server serving doc at its
// root path and counting every GET. The server shuts down via t.Cleanup.
func newCountingJWKSServer(t *testing.T, doc []byte) *countingJWKSServer {
	t.Helper()
	s := &countingJWKSServer{body: append([]byte(nil), doc...)}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.server.Close)
	return s
}

// handle counts the fetch, serves 500 while failing, and otherwise writes
// the current document.
func (s *countingJWKSServer) handle(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetches++
	if s.failing {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	_, _ = w.Write(s.body)
}

// URL returns the fake server's JWKS endpoint URL.
func (s *countingJWKSServer) URL() string {
	return s.server.URL
}

// setJWKS swaps the served document — the rotation and rotation-overlap lever.
func (s *countingJWKSServer) setJWKS(doc []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = append([]byte(nil), doc...)
}

// setFailing toggles 500 responses — the failed-fetch lever.
func (s *countingJWKSServer) setFailing(failing bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failing = failing
}

// fetchCount returns how many times the JWKS document has been fetched.
func (s *countingJWKSServer) fetchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

// jwksFakeClock returns a deterministic clock reading a fixed instant plus a
// function advancing it — the injected clock TTL and window expiry drive.
func jwksFakeClock(start time.Time) (func() time.Time, func(time.Duration)) {
	var mu sync.Mutex
	now := start
	read := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}
	return read, advance
}

// verifyToken runs the signature stage of inbound verification exactly as
// Verifier.Verify will: the kid comes from the token's own protected header,
// resolves through the cache, and the Ed25519 signature must verify under the
// selected key.
func verifyToken(t *testing.T, c *jwksCache, tok string) error {
	t.Helper()
	hdr, _, _, err := jws.Parse([]byte(tok))
	require.NoError(t, err, "test tokens must parse")
	key, err := c.signingKey(context.Background(), hdr.Kid)
	if err != nil {
		return err
	}
	_, _, err = jws.VerifyEd25519(key, []byte(tok))
	return err
}

// TestJWKSCacheKidOnlySelection asserts kid-only selection on a counting
// JWKS server: a token under the served signing key verifies with exactly
// one fetch, a second token hits the cache with no fetch, and a token whose
// header kid names the served X25519 use:enc key denies with ErrUnknownKid —
// the enc key is never usable for signatures, and its deterministic miss
// costs no refetch.
func TestJWKSCacheKidOnlySelection(t *testing.T) {
	signer := newTestSigner(t)
	const encKid = "enc-recipient-kid"
	srv := newCountingJWKSServer(t, jwksDoc(t, signer.sigJWK(t), encX25519JWK(t, encKid)))
	clock, _ := jwksFakeClock(time.Unix(1_700_000_000, 0))
	cache := newJWKSCache(srv.URL(), http.DefaultClient, jwksCacheTestTTL, jwksCacheTestWindow, clock)

	require.NoError(t, verifyToken(t, cache, signer.mint(t)),
		"a token under the served signing key must verify")
	assert.Equal(t, 1, srv.fetchCount(),
		"the first verification must fetch the JWKS exactly once")

	require.NoError(t, verifyToken(t, cache, signer.mint(t)),
		"a second token under the same key must verify from the cache")
	assert.Equal(t, 1, srv.fetchCount(), "a cache hit must not refetch")

	err := verifyToken(t, cache, signer.mintAs(t, encKid))
	assert.ErrorIs(t, err, ErrUnknownKid,
		"an X25519 use:enc kid must never resolve to a signature key")
	assert.Equal(t, 1, srv.fetchCount(),
		"a kid present only as a non-signing key must deny without a refetch")
}

// TestJWKSCacheTTLExpiry asserts the TTL refresh: inside the TTL the cache
// serves without fetching, exactly TTL after the last fetch one refetch
// occurs, and a failed refresh keeps the last good set — its keys keep
// verifying until a later refresh succeeds.
func TestJWKSCacheTTLExpiry(t *testing.T) {
	signer := newTestSigner(t)
	srv := newCountingJWKSServer(t, jwksDoc(t, signer.sigJWK(t)))
	clock, advance := jwksFakeClock(time.Unix(1_700_000_000, 0))
	cache := newJWKSCache(srv.URL(), http.DefaultClient, jwksCacheTestTTL, jwksCacheTestWindow, clock)

	require.NoError(t, verifyToken(t, cache, signer.mint(t)))
	require.Equal(t, 1, srv.fetchCount())

	advance(time.Minute)
	require.NoError(t, verifyToken(t, cache, signer.mint(t)))
	assert.Equal(t, 1, srv.fetchCount(), "inside the TTL the cache must not refetch")

	advance(jwksCacheTestTTL - time.Minute) // exactly TTL after the fetch
	require.NoError(t, verifyToken(t, cache, signer.mint(t)))
	assert.Equal(t, 2, srv.fetchCount(), "past the TTL exactly one refetch must occur")

	srv.setFailing(true)
	advance(jwksCacheTestTTL)
	require.NoError(t, verifyToken(t, cache, signer.mint(t)),
		"a failed refresh must keep the last good set usable")
	assert.Equal(t, 3, srv.fetchCount(), "the failed refresh must have been attempted")

	srv.setFailing(false)
	advance(jwksCacheTestTTL)
	require.NoError(t, verifyToken(t, cache, signer.mint(t)),
		"a recovered server must be refreshed on the next TTL expiry")
	assert.Equal(t, 4, srv.fetchCount(), "the successful refresh must fetch exactly once")
}

// TestJWKSCacheOneRateLimitedRefetchThenDeny asserts the global refetch
// window: an unknown kid whose key the refetch brings in verifies after
// exactly one refetch; every later unknown kid inside the window denies with
// ErrUnknownKid and no fetch; once the window passes one new refetch is
// allowed.
func TestJWKSCacheOneRateLimitedRefetchThenDeny(t *testing.T) {
	current := newTestSigner(t)
	rotated := newTestSigner(t) // the gateway starts serving it after rotation
	unknown := newTestSigner(t) // the gateway never serves this key
	srv := newCountingJWKSServer(t, jwksDoc(t, current.sigJWK(t)))
	clock, advance := jwksFakeClock(time.Unix(1_700_000_000, 0))
	cache := newJWKSCache(srv.URL(), http.DefaultClient, jwksCacheTestTTL, jwksCacheTestWindow, clock)

	require.NoError(t, verifyToken(t, cache, current.mint(t)))
	require.Equal(t, 1, srv.fetchCount())

	// Rotation: the served JWKS now holds current + previous.
	srv.setJWKS(jwksDoc(t, current.sigJWK(t), rotated.sigJWK(t)))

	require.NoError(t, verifyToken(t, cache, rotated.mint(t)),
		"an unknown kid whose key the gateway now serves must verify after one refetch")
	assert.Equal(t, 2, srv.fetchCount(),
		"the unknown kid must trigger exactly one refetch")

	err := verifyToken(t, cache, unknown.mint(t))
	assert.ErrorIs(t, err, ErrUnknownKid)
	assert.Equal(t, 2, srv.fetchCount(),
		"the next unknown kid in the window must deny with no fetch")

	third := newTestSigner(t)
	err = verifyToken(t, cache, third.mint(t))
	assert.ErrorIs(t, err, ErrUnknownKid)
	assert.Equal(t, 2, srv.fetchCount(),
		"the window's single refetch is global: a further unknown kid never refetches")

	advance(jwksCacheTestWindow)
	err = verifyToken(t, cache, unknown.mint(t))
	assert.ErrorIs(t, err, ErrUnknownKid)
	assert.Equal(t, 3, srv.fetchCount(),
		"once the window passes exactly one new refetch is allowed")
}

// TestJWKSCacheRotationAcceptsPreviousKey asserts rotation overlap: a token
// under the previous key, still listed in the served JWKS alongside the
// current one, verifies straight from the cached set — no refetch and no
// configuration change.
func TestJWKSCacheRotationAcceptsPreviousKey(t *testing.T) {
	current := newTestSigner(t)
	previous := newTestSigner(t)
	srv := newCountingJWKSServer(t, jwksDoc(t, current.sigJWK(t), previous.sigJWK(t)))
	clock, _ := jwksFakeClock(time.Unix(1_700_000_000, 0))
	cache := newJWKSCache(srv.URL(), http.DefaultClient, jwksCacheTestTTL, jwksCacheTestWindow, clock)

	require.NoError(t, verifyToken(t, cache, current.mint(t)))
	require.Equal(t, 1, srv.fetchCount())

	require.NoError(t, verifyToken(t, cache, previous.mint(t)),
		"a token under the previous key listed in the JWKS must verify")
	assert.Equal(t, 1, srv.fetchCount(),
		"the previous key must verify from cache without a refetch")
}
