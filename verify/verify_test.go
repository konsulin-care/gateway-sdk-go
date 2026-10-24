package verify_test

import (
	"context"
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
	"github.com/konsulin-care/gateway-sdk-go/verify"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// c01Self is the recipient identity (verifier "self") the composite
// SDK-VERIFY-C01 tests verify tokens against.
const c01Self = "pty-c01-recipient"

// TestVerifyC01DenyMatrix asserts the composite deny half of SDK-VERIFY-C01
// through the public Verifier: a well-formed delivery token verifies as the
// baseline, then an expired token, a foreign-aud token, a wrong-typ token,
// and a body-mutated token each deny with the matching sentinel, and a
// replayed ticket (its jti consumed on the first presentation) denies with
// ErrReplay — fail closed on every row, no partial accept anywhere.
func TestVerifyC01DenyMatrix(t *testing.T) {
	ctx := context.Background()
	env := newPerKindEnv(t, c01Self)
	const body = `{"invocation_id":"inv-c01","status":"ok"}`

	// Baseline: a well-formed delivery token verifies end to end, so every
	// denial below is a policy verdict, not a broken fixture.
	baseline, err := env.v.Verify(ctx,
		env.mint(t, wire.TypDelivery, deliveryClaims(env.now, c01Self, body)),
		wire.TypDelivery, []byte(body))
	require.NoError(t, err, "a well-formed delivery token must verify")
	assert.Equal(t, []string{c01Self}, baseline.Audience)

	cases := []struct {
		name         string
		typ          string // token header typ; "" omits the member entirely
		verifyTyp    string // typ argument to Verify; "" means TypDelivery
		mutate       func(c map[string]any)
		overrideBody []byte // body passed to Verify; nil means body
		want         error  // sentinel errors.Is must match
	}{
		{
			name: "expired token denies ErrExpired",
			typ:  wire.TypDelivery,
			mutate: func(c map[string]any) {
				c["exp"] = env.now.Add(-testSkew - time.Second).Unix()
			},
			want: verify.ErrExpired,
		},
		{
			name: "foreign aud denies ErrAudience",
			typ:  wire.TypDelivery,
			mutate: func(c map[string]any) {
				c["aud"] = "pty-other-recipient"
			},
			want: verify.ErrAudience,
		},
		{
			name:      "wrong typ denies ErrTyp",
			typ:       wire.TypEvent,
			verifyTyp: wire.TypDelivery,
			want:      verify.ErrTyp,
		},
		{
			name:         "body-mutated token denies ErrBodyHash",
			typ:          wire.TypDelivery,
			overrideBody: []byte(body + "tampered"),
			want:         verify.ErrBodyHash,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := cloneClaims(deliveryClaims(env.now, c01Self, body))
			if tc.mutate != nil {
				tc.mutate(claims)
			}
			verifyTyp := tc.verifyTyp
			if verifyTyp == "" {
				verifyTyp = wire.TypDelivery
			}
			bodyBytes := []byte(body)
			if tc.overrideBody != nil {
				bodyBytes = tc.overrideBody
			}
			tok := env.mint(t, tc.typ, claims)
			_, err := env.v.Verify(ctx, tok, verifyTyp, bodyBytes)
			assert.ErrorIs(t, err, tc.want,
				"every C01 deny row must carry the matching sentinel")
		})
	}

	t.Run("replayed ticket denies ErrReplay", func(t *testing.T) {
		// Verify itself never dedupes; replay denial lives on the consuming
		// paths. The ticket path proves it: rule 6 consumes the jti on the
		// first fully successful presentation, and every later presentation
		// of the same token denies with ErrReplay.
		tok := env.mint(t, wire.TypApproval, approvalClaims(env.now, c01Self))
		_, err := env.v.Ticket(ctx, tok, wire.TypApproval, "referral")
		require.NoError(t, err, "the first presentation must consume the jti")
		_, err = env.v.Ticket(ctx, tok, wire.TypApproval, "referral")
		assert.ErrorIs(t, err, verify.ErrReplay,
			"a replayed token must deny with ErrReplay")
	})
}

// TestVerifyC01PostRotationAccepts asserts the composite acceptance half of
// SDK-VERIFY-C01 through the public Verifier: before rotation a token under
// the gateway's only signing key verifies with the first JWKS fetch; after
// rotation (the served JWKS now holds current + previous) a token signed by
// the new key verifies after exactly one unknown-kid refetch, and a token
// under the old key still verifies straight from the cached overlap set —
// no second refetch and no configuration change.
func TestVerifyC01PostRotationAccepts(t *testing.T) {
	ctx := context.Background()
	previous := newC01Signer(t)
	current := newC01Signer(t)
	srv := newC01JWKSServer(t, c01JWKS(t, previous))

	now := goldenNow
	v, err := verify.NewVerifier(srv.URL(), c01Self,
		verify.WithClock(func() time.Time { return now }))
	require.NoError(t, err)

	const body = `{"event":"rotation","status":"ok"}`
	oldTok := previous.mint(t, wire.TypDelivery, deliveryClaims(now, c01Self, body))

	got, err := v.Verify(ctx, oldTok, wire.TypDelivery, []byte(body))
	require.NoError(t, err, "the old-key token must verify before rotation")
	assert.Equal(t, []string{c01Self}, got.Audience)
	require.Equal(t, 1, srv.fetchCount(), "the first Verify must fetch the JWKS once")

	// Rotation: the gateway now serves current + previous during overlap.
	srv.setJWKS(c01JWKS(t, current, previous))

	newTok := current.mint(t, wire.TypDelivery, deliveryClaims(now, c01Self, body))
	got, err = v.Verify(ctx, newTok, wire.TypDelivery, []byte(body))
	require.NoError(t, err,
		"a token signed by the new key must verify once the JWKS serves current+previous")
	assert.Equal(t, []string{c01Self}, got.Audience)
	assert.Equal(t, 2, srv.fetchCount(),
		"the new key's unknown kid must trigger exactly one refetch")

	got, err = v.Verify(ctx, oldTok, wire.TypDelivery, []byte(body))
	require.NoError(t, err,
		"an old-key token must still verify during the rotation overlap")
	assert.Equal(t, 2, srv.fetchCount(),
		"the previous key must verify from the cached overlap set, no refetch")
}

// c01Signer is one Ed25519 test signing key with its derived kid (RFC 7638
// thumbprint) — the composite tests mint gateway-signed tokens with it.
type c01Signer struct {
	priv ed25519.PrivateKey
	kid  string
}

// newC01Signer generates a fresh Ed25519 key and derives its kid as the RFC
// 7638 thumbprint of the public key, exactly how the gateway names its keys.
//
// Parameters: t is the test.
// Returns: a ready-to-use signer.
func newC01Signer(t *testing.T) *c01Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	raw, err := json.Marshal(map[string]string{
		"crv": "Ed25519",
		"kty": "OKP",
		"x":   base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
	})
	require.NoError(t, err)
	kid, err := jwk.Thumbprint(raw)
	require.NoError(t, err)
	return &c01Signer{priv: priv, kid: kid}
}

// jwk renders the signer's public key as the sig JWK entry a gateway JWKS
// serves for its signing keys.
//
// Parameters: t is the test.
// Returns: the JWK object.
func (s *c01Signer) jwk(t *testing.T) map[string]any {
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

// mint signs one compact token with the signer's key over the raw JSON
// claims, stamping the signer's kid and the given header typ.
//
// Parameters: t is the test; typ is the header typ; claims is the JSON
// claims object.
// Returns: the compact JWS.
func (s *c01Signer) mint(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	tok, err := jws.SignEd25519(s.priv,
		jws.Header{Alg: jws.AlgEdDSA, Kid: s.kid, Typ: typ}, payload)
	require.NoError(t, err)
	return tok
}

// c01JWKS builds one JWKS document from the given signers and asserts it
// passes the fail-closed internal/jwk parser, so no test can accidentally
// serve a document the SDK would refuse to parse.
//
// Parameters: t is the test; signers are the keys the document lists.
// Returns: the raw JWKS document.
func c01JWKS(t *testing.T, signers ...*c01Signer) []byte {
	t.Helper()
	keys := make([]map[string]any, 0, len(signers))
	for _, s := range signers {
		keys = append(keys, s.jwk(t))
	}
	doc, err := json.Marshal(map[string]any{"keys": keys})
	require.NoError(t, err)
	_, err = jwk.ParseJWKS(doc)
	require.NoError(t, err, "every test JWKS must pass the fail-closed parser")
	return doc
}

// c01JWKSServer is a fake gateway JWKS endpoint with a swappable document
// and a fetch counter — the rotation lever the composite rotation test
// drives. It serves on the local loopback listener only.
type c01JWKSServer struct {
	mu      sync.Mutex
	body    []byte
	fetches int
	server  *httptest.Server
}

// newC01JWKSServer starts a local httptest server serving doc at its root
// path and counting every GET. The server shuts down via t.Cleanup.
//
// Parameters: t is the test; doc is the initial JWKS document.
// Returns: the running fake server.
func newC01JWKSServer(t *testing.T, doc []byte) *c01JWKSServer {
	t.Helper()
	s := &c01JWKSServer{body: append([]byte(nil), doc...)}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.fetches++
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.server.Close)
	return s
}

// URL returns the fake server's JWKS endpoint URL.
func (s *c01JWKSServer) URL() string {
	return s.server.URL
}

// setJWKS swaps the served document — the rotation lever.
//
// Parameters: doc is the new JWKS document to serve.
func (s *c01JWKSServer) setJWKS(doc []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = append([]byte(nil), doc...)
}

// fetchCount returns how many times the JWKS document has been fetched.
func (s *c01JWKSServer) fetchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}
