package verify_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/verify"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// TestRecipientRulesAllSixAccept asserts SDK-VERIFY-004 acceptance: a
// well-formed ticket for this recipient passes all six Recipient
// Verification Rules — the approval handoff with the referral scope and
// with an export:<study> scope, the payment access ticket with its
// listing:<id> scope, and the mirrored golden approval and access vectors,
// each presented with the exact scope of the operation being performed.
func TestRecipientRulesAllSixAccept(t *testing.T) {
	ctx := context.Background()

	t.Run("golden approval handoff", func(t *testing.T) {
		v, fixtures := newGoldenVerifier(t, "pty-golden-recipient")
		got, err := v.Ticket(ctx, goldenJWT(t, fixtures["ks-approval.json"]),
			wire.TypApproval, "referral")
		require.NoError(t, err)
		assert.Equal(t, "referral", got.Scope)
		assert.Equal(t, []string{"pty-golden-recipient"}, got.Audience)
		assert.Equal(t, "jti-golden-approval", got.JTI)
	})

	t.Run("golden access ticket", func(t *testing.T) {
		v, fixtures := newGoldenVerifier(t, "pty-golden-provider")
		got, err := v.Ticket(ctx, goldenJWT(t, fixtures["ks-access.json"]),
			wire.TypAccess, "listing:lst-golden")
		require.NoError(t, err)
		assert.Equal(t, "listing:lst-golden", got.Scope)
		assert.Equal(t, []string{"pty-golden-provider"}, got.Audience)
		assert.Equal(t, "jti-golden-access", got.JTI)
	})

	env := newPerKindEnv(t, perKindSelf)

	t.Run("minted approval with referral scope", func(t *testing.T) {
		c := approvalClaims(env.now, perKindSelf)
		c["jti"] = "jti-ticket-accept-referral"
		got, err := env.v.Ticket(ctx, env.mint(t, wire.TypApproval, c),
			wire.TypApproval, "referral")
		require.NoError(t, err)
		assert.Equal(t, "referral", got.Scope)
		assert.Equal(t, []string{perKindSelf}, got.Audience)
		assert.Equal(t, "jti-ticket-accept-referral", got.JTI)
	})

	t.Run("minted approval with export study scope", func(t *testing.T) {
		c := approvalClaims(env.now, perKindSelf)
		c["jti"] = "jti-ticket-accept-export"
		c["scope"] = "export:std-demo"
		got, err := env.v.Ticket(ctx, env.mint(t, wire.TypApproval, c),
			wire.TypApproval, "export:std-demo")
		require.NoError(t, err)
		assert.Equal(t, "export:std-demo", got.Scope)
		assert.Equal(t, "jti-ticket-accept-export", got.JTI)
	})

	t.Run("minted access with listing scope", func(t *testing.T) {
		c := accessClaims(env.now, perKindSelf)
		c["jti"] = "jti-ticket-accept-listing"
		got, err := env.v.Ticket(ctx, env.mint(t, wire.TypAccess, c),
			wire.TypAccess, "listing:lst-test")
		require.NoError(t, err)
		assert.Equal(t, "listing:lst-test", got.Scope)
		assert.Equal(t, "jti-ticket-accept-listing", got.JTI)
	})
}

// TestRecipientRuleScopeMismatchDenies asserts rule 5: the presented scope
// must be well-formed for the ticket's kind and exactly equal the requested
// operation. A scope from another operation, a scope shape belonging to the
// other ticket kind, a missing scope, and an empty requested operation each
// deny with ErrClaims — and a scope-denied ticket does not consume its jti,
// so the same jti presented for the right operation still passes.
func TestRecipientRuleScopeMismatchDenies(t *testing.T) {
	ctx := context.Background()
	env := newPerKindEnv(t, perKindSelf)

	cases := []struct {
		name      string
		typ       string
		mutate    func(c map[string]any)
		wantScope string
	}{
		{
			name: "approval presented for another scope",
			typ:  wire.TypApproval,
			mutate: func(c map[string]any) {
				c["scope"] = "export:std-other"
			},
			wantScope: "referral",
		},
		{
			name: "access presented for another listing",
			typ:  wire.TypAccess,
			mutate: func(c map[string]any) {
				c["scope"] = "listing:lst-other"
			},
			wantScope: "listing:lst-test",
		},
		{
			name: "missing scope",
			typ:  wire.TypApproval,
			mutate: func(c map[string]any) {
				delete(c, "scope")
			},
			wantScope: "referral",
		},
		{
			name: "scope shape of the other ticket kind",
			typ:  wire.TypAccess,
			mutate: func(c map[string]any) {
				c["scope"] = "referral"
			},
			wantScope: "referral",
		},
		{
			name:      "empty requested operation",
			typ:       wire.TypApproval,
			wantScope: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := approvalClaims(env.now, perKindSelf)
			if tc.typ == wire.TypAccess {
				base = accessClaims(env.now, perKindSelf)
			}
			if tc.mutate != nil {
				tc.mutate(base)
			}
			tok := env.mint(t, tc.typ, base)
			_, err := env.v.Ticket(ctx, tok, tc.typ, tc.wantScope)
			assert.ErrorIs(t, err, verify.ErrClaims,
				"a scope violation must deny with ErrClaims")
		})
	}

	t.Run("a scope denial does not consume the jti", func(t *testing.T) {
		c := approvalClaims(env.now, perKindSelf)
		c["jti"] = "jti-ticket-scope-unconsumed"
		c["scope"] = "export:std-demo"
		tok := env.mint(t, wire.TypApproval, c)

		_, err := env.v.Ticket(ctx, tok, wire.TypApproval, "referral")
		require.ErrorIs(t, err, verify.ErrClaims)

		got, err := env.v.Ticket(ctx, tok, wire.TypApproval, "export:std-demo")
		require.NoError(t, err,
			"a ticket denied by an earlier rule must not have consumed its jti")
		assert.Equal(t, "jti-ticket-scope-unconsumed", got.JTI)
	})
}

// TestRecipientRuleJTIOnceOnlyDenies asserts rule 6: the jti is consumed
// exactly once on the first fully successful presentation — every later
// presentation of the same jti denies with ErrReplay (callers map it to
// HTTP 409), the reservation sticks across repeated attempts, and a
// different jti is unaffected. Both ticket kinds behave the same.
func TestRecipientRuleJTIOnceOnlyDenies(t *testing.T) {
	ctx := context.Background()
	env := newPerKindEnv(t, perKindSelf)

	c := approvalClaims(env.now, perKindSelf)
	c["jti"] = "jti-ticket-once-only"
	tok := env.mint(t, wire.TypApproval, c)

	_, err := env.v.Ticket(ctx, tok, wire.TypApproval, "referral")
	require.NoError(t, err, "the first presentation of a fresh jti must pass rule 6")

	_, err = env.v.Ticket(ctx, tok, wire.TypApproval, "referral")
	assert.ErrorIs(t, err, verify.ErrReplay,
		"the second presentation of the same jti must deny")

	_, err = env.v.Ticket(ctx, tok, wire.TypApproval, "referral")
	assert.ErrorIs(t, err, verify.ErrReplay,
		"the jti must stay consumed for every later presentation")

	other := cloneClaims(c)
	other["jti"] = "jti-ticket-once-only-second"
	_, err = env.v.Ticket(ctx, env.mint(t, wire.TypApproval, other),
		wire.TypApproval, "referral")
	require.NoError(t, err, "a different jti must be unaffected by the reservation")

	t.Run("access ticket jti is once-only too", func(t *testing.T) {
		ac := accessClaims(env.now, perKindSelf)
		ac["jti"] = "jti-ticket-once-access"
		at := env.mint(t, wire.TypAccess, ac)

		_, err := env.v.Ticket(ctx, at, wire.TypAccess, "listing:lst-test")
		require.NoError(t, err)
		_, err = env.v.Ticket(ctx, at, wire.TypAccess, "listing:lst-test")
		assert.ErrorIs(t, err, verify.ErrReplay)
	})
}

// TestRecipientRuleWrongTypAndAudDeny asserts rules 2 and 3: only
// ks-approval+jwt and ks-access+jwt are ticket kinds — a delivery, event,
// result, or party typ argument, approval-shaped claims under a delivery
// typ header, and a missing typ header each deny with ErrTyp — and aud must
// be exactly this recipient: a foreign or multi-element aud denies
// with ErrAudience even under a valid gateway signature, and an aud denial
// does not consume the ticket's jti.
func TestRecipientRuleWrongTypAndAudDeny(t *testing.T) {
	ctx := context.Background()
	env := newPerKindEnv(t, perKindSelf)

	t.Run("rule 2 exact typ per operation", func(t *testing.T) {
		cases := []struct {
			name string
			typ  string
			arg  string
		}{
			{
				name: "delivery typ argument",
				typ:  wire.TypDelivery,
				arg:  wire.TypDelivery,
			},
			{
				name: "event typ argument",
				typ:  wire.TypEvent,
				arg:  wire.TypEvent,
			},
			{
				name: "result typ argument",
				typ:  wire.TypResult,
				arg:  wire.TypResult,
			},
			{
				name: "party typ argument",
				typ:  wire.TypParty,
				arg:  wire.TypParty,
			},
			{
				name: "approval claims under a delivery typ header",
				typ:  wire.TypDelivery,
				arg:  wire.TypApproval,
			},
			{
				name: "missing typ header",
				typ:  "",
				arg:  wire.TypApproval,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				c := approvalClaims(env.now, perKindSelf)
				tok := env.mint(t, tc.typ, c)
				_, err := env.v.Ticket(ctx, tok, tc.arg, "referral")
				assert.ErrorIs(t, err, verify.ErrTyp,
					"any typ other than the two ticket kinds must deny with ErrTyp")
			})
		}
	})

	t.Run("rule 3 audience equals self", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(c map[string]any)
		}{
			{
				name: "foreign aud",
				mutate: func(c map[string]any) {
					c["aud"] = "pty-other-party"
				},
			},
			{
				name: "multi-element aud",
				mutate: func(c map[string]any) {
					c["aud"] = []string{perKindSelf, "pty-other-party"}
				},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				c := approvalClaims(env.now, perKindSelf)
				tc.mutate(c)
				tok := env.mint(t, wire.TypApproval, c)
				_, err := env.v.Ticket(ctx, tok, wire.TypApproval, "referral")
				assert.ErrorIs(t, err, verify.ErrAudience,
					"aud must equal this recipient exactly")
			})
		}
	})

	t.Run("an aud denial does not consume the jti", func(t *testing.T) {
		c := approvalClaims(env.now, perKindSelf)
		c["jti"] = "jti-ticket-aud-unconsumed"
		c["aud"] = "pty-other-party"
		tok := env.mint(t, wire.TypApproval, c)

		_, err := env.v.Ticket(ctx, tok, wire.TypApproval, "referral")
		require.ErrorIs(t, err, verify.ErrAudience)

		c["aud"] = perKindSelf
		got, err := env.v.Ticket(ctx, env.mint(t, wire.TypApproval, c),
			wire.TypApproval, "referral")
		require.NoError(t, err,
			"a ticket denied by rule 3 must not have consumed its jti")
		assert.Equal(t, "jti-ticket-aud-unconsumed", got.JTI)
	})
}

// TestRecipientRuleSignatureIssuerExpiryDeny asserts rules 1, 3, and 4 each
// deny on their own: a signature made by another key under the served kid
// (ErrSignature), a token whose kid is absent from the gateway JWKS
// (ErrUnknownKid), a foreign iss (ErrIssuer), and an exp beyond the
// 60-second skew (ErrExpired) — and a ticket denied by any of these rules
// does not consume its jti either.
func TestRecipientRuleSignatureIssuerExpiryDeny(t *testing.T) {
	ctx := context.Background()
	env := newPerKindEnv(t, perKindSelf)
	foreign := newForeignSigner(t)

	t.Run("rule 1 bad signature under the served kid", func(t *testing.T) {
		c := approvalClaims(env.now, perKindSelf)
		c["jti"] = "jti-ticket-bad-signature"
		tok := signApproval(t, foreign.priv, env.kid, c)
		_, err := env.v.Ticket(ctx, tok, wire.TypApproval, "referral")
		assert.ErrorIs(t, err, verify.ErrSignature,
			"a signature that does not verify under the kid-selected key must deny")
	})

	t.Run("rule 1 unknown kid", func(t *testing.T) {
		c := approvalClaims(env.now, perKindSelf)
		c["jti"] = "jti-ticket-unknown-kid"
		tok := signApproval(t, foreign.priv, foreign.kid, c)
		_, err := env.v.Ticket(ctx, tok, wire.TypApproval, "referral")
		assert.ErrorIs(t, err, verify.ErrUnknownKid,
			"a kid absent from the gateway JWKS must deny")
	})

	t.Run("rule 3 foreign iss", func(t *testing.T) {
		c := approvalClaims(env.now, perKindSelf)
		c["iss"] = "some-other-issuer"
		tok := env.mint(t, wire.TypApproval, c)
		_, err := env.v.Ticket(ctx, tok, wire.TypApproval, "referral")
		assert.ErrorIs(t, err, verify.ErrIssuer,
			"iss must be the literal gateway")
	})

	t.Run("rule 4 expired beyond the skew", func(t *testing.T) {
		c := approvalClaims(env.now, perKindSelf)
		c["jti"] = "jti-ticket-exp-unconsumed"
		c["exp"] = env.now.Add(-testSkew - time.Second).Unix()
		tok := env.mint(t, wire.TypApproval, c)

		_, err := env.v.Ticket(ctx, tok, wire.TypApproval, "referral")
		require.ErrorIs(t, err, verify.ErrExpired)

		c["exp"] = env.now.Add(5 * time.Minute).Unix()
		got, err := env.v.Ticket(ctx, env.mint(t, wire.TypApproval, c),
			wire.TypApproval, "referral")
		require.NoError(t, err,
			"a ticket denied by rule 4 must not have consumed its jti")
		assert.Equal(t, "jti-ticket-exp-unconsumed", got.JTI)
	})
}

// foreignSigner is an Ed25519 key pair whose kid no fake JWKS serves. It
// mints the rule-1 violation tokens: its signature under the served kid
// (bad signature) and its own kid (unknown kid).
type foreignSigner struct {
	priv ed25519.PrivateKey
	kid  string
}

// newForeignSigner generates a fresh Ed25519 key and derives its RFC 7638
// thumbprint kid, which the test env's JWKS never serves.
//
// Parameters: t is the test.
// Returns: a ready-to-use foreignSigner.
func newForeignSigner(t *testing.T) foreignSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub, ok := priv.Public().(ed25519.PublicKey)
	require.True(t, ok, "ed25519 private key public half must be an ed25519.PublicKey")
	key := jwk.Key{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
	kid, err := key.Thumbprint()
	require.NoError(t, err)
	return foreignSigner{priv: priv, kid: kid}
}

// signApproval signs claims as a ks-approval+jwt with the given key and
// header kid, giving the rule-1 tests full header control the env's mint
// helper does not expose.
//
// Parameters: t is the test; priv is the signing key; kid is the header kid;
// claims is the JSON claims object.
// Returns: the compact JWS.
func signApproval(t *testing.T, priv ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	tok, err := jws.SignEd25519(priv,
		jws.Header{Alg: jws.AlgEdDSA, Kid: kid, Typ: wire.TypApproval}, payload)
	require.NoError(t, err)
	return tok
}
