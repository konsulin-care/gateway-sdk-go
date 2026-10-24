package verify_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/verify"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// testSkew mirrors the contract's 60-second clock skew on exp and iat; the
// boundary cases assert exactly where acceptance ends.
const testSkew = 60 * time.Second

// TestPerKindChecksAcceptValidTokens asserts SDK-VERIFY-002 acceptance: every
// golden vector (with the clock fixed inside its validity window) and every
// well-formed minted token of each gateway-signed kind verifies — approval,
// access, delivery with and without the conditional user_ref/payment_id, one
// event per accepted purpose, and result — plus a single-element aud array
// and a token carrying unknown claim names.
func TestPerKindChecksAcceptValidTokens(t *testing.T) {
	ctx := context.Background()

	t.Run("golden vectors", func(t *testing.T) {
		cases := []struct {
			file string
			typ  string
			self string
		}{
			{"ks-approval.json", wire.TypApproval, "pty-golden-recipient"},
			{"ks-access.json", wire.TypAccess, "pty-golden-provider"},
			{"ks-delivery.json", wire.TypDelivery, "pty-golden-engine"},
			{"ks-event-service-result.json", wire.TypEvent, "pty-golden-provider"},
			{"ks-result.json", wire.TypResult, "pty-golden-engine"},
		}
		for _, tc := range cases {
			t.Run(tc.file, func(t *testing.T) {
				v, fixtures := newGoldenVerifier(t, tc.self)
				fx := fixtures[tc.file]

				got, err := v.Verify(ctx, goldenJWT(t, fx), tc.typ, goldenBody(t, fx))
				require.NoError(t, err)
				assert.Equal(t, "gateway", got.Iss)
				require.Len(t, got.Audience, 1)
				assert.Equal(t, tc.self, got.Audience[0])
			})
		}
	})

	t.Run("minted tokens", func(t *testing.T) {
		env := newPerKindEnv(t, perKindSelf)
		const body = `{"invocation_id":"inv-1"}`

		t.Run("approval", func(t *testing.T) {
			tok := env.mint(t, wire.TypApproval, approvalClaims(env.now, perKindSelf))
			got, err := env.v.Verify(ctx, tok, wire.TypApproval, nil)
			require.NoError(t, err)
			assert.Equal(t, "referral", got.Scope)
			assert.Equal(t, "referral", got.Purpose)
			assert.Equal(t, "jti-test-approval", got.JTI)
		})

		t.Run("access", func(t *testing.T) {
			tok := env.mint(t, wire.TypAccess, accessClaims(env.now, perKindSelf))
			got, err := env.v.Verify(ctx, tok, wire.TypAccess, nil)
			require.NoError(t, err)
			assert.Equal(t, "listing:lst-test", got.Scope)
			assert.Equal(t, "jti-test-access", got.JTI)
		})

		t.Run("delivery with user_ref and payment_id", func(t *testing.T) {
			c := deliveryClaims(env.now, perKindSelf, body)
			c["user_ref"] = "usr-test"
			c["payment_id"] = "pay-test"
			tok := env.mint(t, wire.TypDelivery, c)
			got, err := env.v.Verify(ctx, tok, wire.TypDelivery, []byte(body))
			require.NoError(t, err)
			assert.Equal(t, "usr-test", got.UserRef)
			assert.Equal(t, "pay-test", got.PaymentID)
			assert.Equal(t, "wh-test-delivery", got.WebhookID)
		})

		t.Run("delivery without conditional claims", func(t *testing.T) {
			tok := env.mint(t, wire.TypDelivery, deliveryClaims(env.now, perKindSelf, body))
			got, err := env.v.Verify(ctx, tok, wire.TypDelivery, []byte(body))
			require.NoError(t, err, "user_ref and payment_id are conditional, never required")
			assert.Empty(t, got.UserRef)
			assert.Empty(t, got.PaymentID)
		})

		for _, purpose := range []string{
			wire.PurposeSettlementNotification,
			wire.PurposeServiceResult,
			wire.PurposePaymentRequired,
			wire.PurposeServiceReceipt,
		} {
			t.Run("event "+purpose, func(t *testing.T) {
				c := eventClaims(env.now, perKindSelf, body, purpose)
				tok := env.mint(t, wire.TypEvent, c)
				got, err := env.v.Verify(ctx, tok, wire.TypEvent, []byte(body))
				require.NoError(t, err)
				assert.Equal(t, purpose, got.Purpose)
			})
		}

		t.Run("result", func(t *testing.T) {
			tok := env.mint(t, wire.TypResult, resultClaims(env.now, perKindSelf))
			got, err := env.v.Verify(ctx, tok, wire.TypResult, nil)
			require.NoError(t, err)
			assert.Equal(t, wire.PurposeWebhookResult, got.Purpose)
			assert.Equal(t, "wh-test-result", got.WebhookID)
		})

		t.Run("aud as single-element array", func(t *testing.T) {
			c := deliveryClaims(env.now, perKindSelf, body)
			c["aud"] = []string{perKindSelf}
			tok := env.mint(t, wire.TypDelivery, c)
			got, err := env.v.Verify(ctx, tok, wire.TypDelivery, []byte(body))
			require.NoError(t, err, "a single-element aud array equal to self must be accepted")
			assert.Equal(t, []string{perKindSelf}, got.Audience)
		})

		t.Run("unknown claim names are ignored", func(t *testing.T) {
			c := deliveryClaims(env.now, perKindSelf, body)
			c["future_claim"] = "ignored"
			tok := env.mint(t, wire.TypDelivery, c)
			_, err := env.v.Verify(ctx, tok, wire.TypDelivery, []byte(body))
			require.NoError(t, err, "unknown claim names never deny (SDK-WIRE-004)")
		})

		t.Run("iat and exp inside the 60s skew are accepted", func(t *testing.T) {
			c := deliveryClaims(env.now, perKindSelf, body)
			c["iat"] = env.now.Add(testSkew - time.Second).Unix()
			c["exp"] = env.now.Add(-testSkew + time.Second).Unix()
			tok := env.mint(t, wire.TypDelivery, c)
			_, err := env.v.Verify(ctx, tok, wire.TypDelivery, []byte(body))
			require.NoError(t, err, "exp inside the skew window must not deny")
		})
	})
}

// TestPerKindChecksDenyMatrix asserts the SDK-VERIFY-002 denial matrix: a
// mutated delivery token per case, each denied fail-closed with exactly the
// sentinel matching the violated rule — wrong/missing typ, wrong purpose, a
// missing required claim, foreign iss or aud, a multi-element aud, expired
// exp beyond the 60s skew, iat beyond now+60s, a mutated body, and the
// party-signed kind.
func TestPerKindChecksDenyMatrix(t *testing.T) {
	env := newPerKindEnv(t, perKindSelf)
	const body = `{"invocation_id":"inv-matrix"}`
	base := deliveryClaims(env.now, perKindSelf, body)

	cases := []struct {
		name         string
		typ          string // token header typ; "" omits the member entirely
		verifyTyp    string // typ argument to Verify; "" means TypDelivery
		mutate       func(c map[string]any)
		overrideBody []byte // body passed to Verify; nil means body
		want         error  // sentinel errors.Is must match; nil means accept
	}{
		{
			name:      "wrong typ denies ErrTyp",
			typ:       wire.TypApproval,
			verifyTyp: wire.TypDelivery,
			want:      verify.ErrTyp,
		},
		{
			name:      "missing typ denies ErrTyp",
			typ:       "",
			verifyTyp: wire.TypDelivery,
			want:      verify.ErrTyp,
		},
		{
			name: "wrong purpose denies ErrPurpose",
			typ:  wire.TypDelivery,
			mutate: func(c map[string]any) {
				c["purpose"] = wire.PurposeSettlementNotification
			},
			want: verify.ErrPurpose,
		},
		{
			name: "missing required claim denies ErrClaims",
			typ:  wire.TypDelivery,
			mutate: func(c map[string]any) {
				delete(c, "webhook_id")
			},
			want: verify.ErrClaims,
		},
		{
			name: "missing iat denies ErrClaims",
			typ:  wire.TypDelivery,
			mutate: func(c map[string]any) {
				delete(c, "iat")
			},
			want: verify.ErrClaims,
		},
		{
			name: "foreign iss denies ErrIssuer",
			typ:  wire.TypDelivery,
			mutate: func(c map[string]any) {
				c["iss"] = "evil-issuer"
			},
			want: verify.ErrIssuer,
		},
		{
			name: "foreign aud denies ErrAudience",
			typ:  wire.TypDelivery,
			mutate: func(c map[string]any) {
				c["aud"] = "pty-other"
			},
			want: verify.ErrAudience,
		},
		{
			name: "multi-element aud denies ErrAudience",
			typ:  wire.TypDelivery,
			mutate: func(c map[string]any) {
				c["aud"] = []string{perKindSelf, "pty-other"}
			},
			want: verify.ErrAudience,
		},
		{
			name: "exp beyond the 60s skew denies ErrExpired",
			typ:  wire.TypDelivery,
			mutate: func(c map[string]any) {
				c["exp"] = env.now.Add(-testSkew - time.Second).Unix()
			},
			want: verify.ErrExpired,
		},
		{
			name: "iat beyond now plus 60s denies ErrClaims",
			typ:  wire.TypDelivery,
			mutate: func(c map[string]any) {
				c["iat"] = env.now.Add(testSkew + time.Second).Unix()
			},
			want: verify.ErrClaims,
		},
		{
			name:         "mutated body denies ErrBodyHash",
			typ:          wire.TypDelivery,
			overrideBody: []byte(body + "tampered"),
			want:         verify.ErrBodyHash,
		},
		{
			name:      "party-signed kind denies ErrUnsupportedKind",
			typ:       wire.TypParty,
			verifyTyp: wire.TypParty,
			want:      verify.ErrUnsupportedKind,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := cloneClaims(base)
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
			_, err := env.v.Verify(context.Background(), tok, verifyTyp, bodyBytes)
			assert.ErrorIs(t, err, tc.want, "denial must carry the matching sentinel")
		})
	}
}

// TestEventPurposeFourAcceptedOthersDeny asserts the SDK-VERIFY-002 event
// purpose rule verbatim: ks-event+jwt accepts exactly settlement-notification,
// service-result, payment-required, and service-receipt; every other purpose
// value — including legitimate purposes of other kinds — denies with
// ErrPurpose.
func TestEventPurposeFourAcceptedOthersDeny(t *testing.T) {
	env := newPerKindEnv(t, perKindSelf)
	const body = `{"result_id":"res-1","status":"succeeded"}`

	for _, purpose := range []string{
		wire.PurposeSettlementNotification,
		wire.PurposeServiceResult,
		wire.PurposePaymentRequired,
		wire.PurposeServiceReceipt,
	} {
		t.Run("accept "+purpose, func(t *testing.T) {
			c := eventClaims(env.now, perKindSelf, body, purpose)
			tok := env.mint(t, wire.TypEvent, c)
			got, err := env.v.Verify(context.Background(), tok, wire.TypEvent, []byte(body))
			require.NoError(t, err)
			assert.Equal(t, purpose, got.Purpose)
		})
	}

	for _, purpose := range []string{
		wire.PurposeWebhookDelivery,
		wire.PurposeWebhookResult,
		wire.PurposeAdminAuth,
		"not-a-purpose",
	} {
		t.Run("deny "+purpose, func(t *testing.T) {
			c := eventClaims(env.now, perKindSelf, body, purpose)
			tok := env.mint(t, wire.TypEvent, c)
			_, err := env.v.Verify(context.Background(), tok, wire.TypEvent, []byte(body))
			assert.ErrorIs(t, err, verify.ErrPurpose)
		})
	}
}
