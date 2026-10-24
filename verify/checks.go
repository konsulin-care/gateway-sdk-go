package verify

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"slices"
	"time"

	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// clockSkew is the allowed clock skew on exp and iat — the 60-second skew of
// the Recipient Verification Rules and SDK-VERIFY-002.
const clockSkew = 60 * time.Second

// gatewayIssuer is the only iss value Verify accepts.
const gatewayIssuer = "gateway"

// eventPurposes are exactly the four ks-event+jwt purposes accepted
// (SDK-VERIFY-002): the two originals plus the two hardening-era pushes.
var eventPurposes = []string{
	wire.PurposeSettlementNotification,
	wire.PurposeServiceResult,
	wire.PurposePaymentRequired,
	wire.PurposeServiceReceipt,
}

// Verify verifies one inbound gateway token of kind typ against the cached
// gateway JWKS and the exact body bytes (SDK-VERIFY-002), fail-closed in
// this order: supported kind (ks-party+jwt denies ErrUnsupportedKind before
// any signature work), structural parse and exact typ (ErrTyp), kid-only
// key selection (ErrUnknownKid) and Ed25519 signature (ErrSignature),
// required claims from the Token Kinds table row (ErrClaims), iss gateway
// (ErrIssuer), aud equal to self as a string or single-element array
// (ErrAudience), exp and iat within the 60-second skew (ErrExpired /
// ErrClaims), the kind's purpose rules (ErrPurpose), and body_sha256 over
// body on delivery/event tokens (ErrBodyHash). Every sentinel is matchable
// with errors.Is. Unknown claim names are ignored (SDK-WIRE-004); the
// signature key comes only from the JWKS, selected by the token's own header
// kid. Verify does not dedupe — replay reservation is the middleware's and
// Ticket's job, after these checks pass.
//
// Parameters: ctx carries cancellation into any JWKS fetch; token is the
// compact JWS; typ is the expected kind (one of the wire typ constants);
// body is the exact request body bytes the token's body_sha256 covers
// (nil for kinds without a body).
// Returns: the verified Claims and nil, or an error carrying the matching
// sentinel (errors.Is). Never panics.
func (v *Verifier) Verify(ctx context.Context, token, typ string, body []byte) (Claims, error) {
	kind, err := supportedKind(typ)
	if err != nil {
		return Claims{}, err
	}
	hdr, err := parseToken(token, typ)
	if err != nil {
		return Claims{}, err
	}
	payload, err := v.verifySignature(ctx, token, hdr)
	if err != nil {
		return Claims{}, err
	}
	raw, err := parseRawClaims(payload)
	if err != nil {
		return Claims{}, fmt.Errorf("verify: %w: %v", ErrClaims, err)
	}
	if err := requireKindClaims(raw, kind); err != nil {
		return Claims{}, err
	}
	if err := checkIssuer(raw); err != nil {
		return Claims{}, err
	}
	if err := checkAudience(raw, v.self); err != nil {
		return Claims{}, err
	}
	if err := checkTimes(raw, v.clock()); err != nil {
		return Claims{}, err
	}
	if err := checkPurpose(raw, typ); err != nil {
		return Claims{}, err
	}
	if err := checkBodyHash(raw, typ, body); err != nil {
		return Claims{}, err
	}
	return raw.claims(typ), nil
}

// supportedKind looks the kind up before any token work: ks-party+jwt is
// party-signed and never verifiable against the gateway JWKS, so it denies
// with ErrUnsupportedKind; a typ outside the Token Kinds table denies with
// ErrTyp (deny unknown typ — RFC 8725 section 3.11).
//
// Parameters: typ is the expected token kind.
// Returns: the table row and nil, or an error carrying the sentinel.
func supportedKind(typ string) (wire.TokenKind, error) {
	if typ == wire.TypParty {
		return wire.TokenKind{}, fmt.Errorf("verify: %w: %s is signed by the party key, not the gateway", ErrUnsupportedKind, typ)
	}
	kind, ok := wire.KindForTyp(typ)
	if !ok {
		return wire.TokenKind{}, fmt.Errorf("verify: %w: unknown typ %q", ErrTyp, typ)
	}
	return kind, nil
}

// parseToken structurally parses the compact JWS (without verifying) and
// applies the exact typ and alg allow-list for the expected kind: any
// mismatch — including a missing typ header member — denies with ErrTyp; a
// structurally invalid token denies with ErrSignature.
//
// Parameters: token is the compact JWS; typ is the expected kind.
// Returns: the protected header and nil, or an error carrying the sentinel.
func parseToken(token, typ string) (jws.Header, error) {
	hdr, _, _, err := jws.Parse([]byte(token))
	if err != nil {
		return jws.Header{}, fmt.Errorf("verify: %w: %v", ErrSignature, err)
	}
	if err := jws.CheckKind(hdr, typ); err != nil {
		return jws.Header{}, fmt.Errorf("verify: %w: %v", ErrTyp, err)
	}
	return hdr, nil
}

// verifySignature resolves the token's header kid against the cached
// gateway JWKS (kid-only, one rate-limited refetch, then ErrUnknownKid) and
// verifies the Ed25519 signature over the token's exact signing input; any
// signature failure denies with ErrSignature. A JWKS fetch failure with no
// cached set denies with the fetch error (nothing can verify without a
// first good set).
//
// Parameters: ctx carries cancellation into any fetch; token is the compact
// JWS; hdr is the already-parsed header.
// Returns: the raw payload and nil, or an error carrying the sentinel.
func (v *Verifier) verifySignature(ctx context.Context, token string, hdr jws.Header) ([]byte, error) {
	key, err := v.cache.signingKey(ctx, hdr.Kid)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	_, payload, err := jws.VerifyEd25519(key, []byte(token))
	if err != nil {
		return nil, fmt.Errorf("verify: %w: %v", ErrSignature, err)
	}
	return payload, nil
}

// requireKindClaims enforces the Token Kinds table row: every claim the row
// lists as required must be present and usable (non-empty string, number for
// iat/exp, non-empty aud). Conditional claims (user_ref, payment_id) are
// never required and never checked here. A missing claim denies with
// ErrClaims.
//
// Parameters: raw is the decoded claims; kind is the table row for the
// token's typ.
// Returns: nil when every required claim is present, else ErrClaims.
func requireKindClaims(raw rawClaims, kind wire.TokenKind) error {
	for _, name := range kind.Claims {
		if !raw.present(name) {
			return fmt.Errorf("verify: %w: required claim %q missing for %s", ErrClaims, name, kind.Typ)
		}
	}
	return nil
}

// checkIssuer enforces iss = "gateway" (rule 3 of the Recipient
// Verification Rules; SDK-VERIFY-002). Any other value — foreign or empty —
// denies with ErrIssuer.
//
// Parameters: raw is the decoded claims.
// Returns: nil when iss is exactly "gateway", else ErrIssuer.
func checkIssuer(raw rawClaims) error {
	iss, _ := raw.str("iss")
	if iss != gatewayIssuer {
		return fmt.Errorf("verify: %w: iss %q", ErrIssuer, iss)
	}
	return nil
}

// checkAudience enforces aud = self: a string or a single-element array
// equal to this verifier's identity passes; a multi-element array, an empty
// or wrong-typed aud, or any other value denies with ErrAudience (fail
// closed — no first-match search through multiple audiences). The compare is
// constant-time.
//
// Parameters: raw is the decoded claims; self is the recipient identity.
// Returns: nil when aud identifies this recipient, else ErrAudience.
func checkAudience(raw rawClaims, self string) error {
	aud, ok := raw.audiences("aud")
	if !ok || len(aud) != 1 ||
		subtle.ConstantTimeCompare([]byte(aud[0]), []byte(self)) != 1 {
		return fmt.Errorf("verify: %w: aud must be a single value equal to this recipient", ErrAudience)
	}
	return nil
}

// checkTimes enforces exp and iat within the 60-second skew: exp beyond
// now+skew denies with ErrExpired (exp inside the skew still verifies);
// iat more than skew in the future denies with ErrClaims. A missing or
// non-numeric value has already denied in requireKindClaims, and denies
// again here fail-closed if reached alone.
//
// Parameters: raw is the decoded claims; now is the verifier's clock
// instant.
// Returns: nil when both timestamps sit inside the window, else the
// matching sentinel.
func checkTimes(raw rawClaims, now time.Time) error {
	exp, ok := raw.seconds("exp")
	if !ok || now.After(exp.Add(clockSkew)) {
		return fmt.Errorf("verify: %w: exp outside the %s skew window", ErrExpired, clockSkew)
	}
	iat, ok := raw.seconds("iat")
	if !ok {
		return fmt.Errorf("verify: %w: iat missing or not a number", ErrClaims)
	}
	if iat.After(now.Add(clockSkew)) {
		return fmt.Errorf("verify: %w: iat is more than %s in the future", ErrClaims, clockSkew)
	}
	return nil
}

// checkPurpose enforces the kind's purpose rule: delivery is pinned to
// webhook-delivery, event accepts exactly the four event purposes, result is
// pinned to webhook-result, and approval/access require a non-empty purpose
// (their value is operation-scoped and checked by the ticket rules). Any
// other value denies with ErrPurpose.
//
// Parameters: raw is the decoded claims; typ is the token kind.
// Returns: nil when the purpose is allowed, else ErrPurpose.
func checkPurpose(raw rawClaims, typ string) error {
	purpose, _ := raw.str("purpose")
	if !purposeAllowed(typ, purpose) {
		return fmt.Errorf("verify: %w: purpose %q is not allowed for %s", ErrPurpose, purpose, typ)
	}
	return nil
}

// purposeAllowed applies the per-kind purpose rule of checkPurpose.
//
// Parameters: typ is the token kind; purpose is the decoded purpose claim.
// Returns: true when the purpose is allowed for the kind.
func purposeAllowed(typ, purpose string) bool {
	switch typ {
	case wire.TypDelivery:
		return purpose == wire.PurposeWebhookDelivery
	case wire.TypEvent:
		return slices.Contains(eventPurposes, purpose)
	case wire.TypResult:
		return purpose == wire.PurposeWebhookResult
	case wire.TypApproval, wire.TypAccess:
		return purpose != ""
	default:
		return false
	}
}

// checkBodyHash enforces body_sha256 on delivery and event tokens: the
// claim must equal the base64url (unpadded) SHA-256 of the exact body
// bytes, compared in constant time. A mismatch — including a mutated body —
// denies with ErrBodyHash; a missing claim denies with ErrClaims (already
// covered by the table row, restated here fail-closed). Kinds without a
// body never check it.
//
// Parameters: raw is the decoded claims; typ is the token kind; body is the
// exact request body bytes.
// Returns: nil when the digest matches or the kind carries no body, else
// the matching sentinel.
func checkBodyHash(raw rawClaims, typ string, body []byte) error {
	if typ != wire.TypDelivery && typ != wire.TypEvent {
		return nil
	}
	want, ok := raw.str("body_sha256")
	if !ok {
		return fmt.Errorf("verify: %w: body_sha256 missing or not a string", ErrClaims)
	}
	sum := sha256.Sum256(body)
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("verify: %w: body_sha256 does not cover the body", ErrBodyHash)
	}
	return nil
}
