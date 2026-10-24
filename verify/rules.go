package verify

import (
	"context"
	"fmt"
	"strings"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// Ticket verifies one directly presented ticket — the approval handoff
// (ks-approval+jwt) or the payment access ticket (ks-access+jwt) — against
// the six Recipient Verification Rules of SDK-VERIFY-004, fail-closed with
// rule 6 last: first the caller's expected typ must be exactly one of the
// two ticket kinds (rule 2: any other typ, including ks-delivery+jwt and
// the party-signed ks-party+jwt, denies with ErrTyp before any token work,
// and a token whose own header typ differs from typ denies inside Verify
// with the same sentinel), then Verify runs the signature-by-header-kid,
// iss, aud, exp-within-60s-skew, purpose, and Token Kinds row checks
// (rules 1, 3, 4 with ErrSignature, ErrUnknownKid, ErrIssuer, ErrAudience,
// ErrExpired), then the presented scope must be well-formed for the
// ticket's kind — referral or export:<study> on an approval, listing:<id>
// on an access ticket — and exactly equal wantScope, the scope of the
// operation the caller is about to perform (rule 5: ErrClaims, and a
// missing scope has already denied as a required claim). Only after every
// earlier rule passes is the jti consumed in the ReplayCache under
// ScopeJTI until exp plus the 60-second skew (rule 6), so a ticket denied
// by any earlier rule never spends its jti; a repeated jti denies with
// ErrReplay (callers map it to HTTP 409). A ReplayCache error denies — a
// cache that cannot record must not let a ticket through.
//
// Parameters: ctx carries cancellation into any JWKS fetch; token is the
// compact ticket JWS; typ is the expected ticket kind — wire.TypApproval
// or wire.TypAccess; wantScope is the exact scope of the operation about
// to be performed (referral, export:<study>, or listing:<id>).
// Returns: the verified Claims and nil, or an error carrying the matching
// sentinel (errors.Is). Never panics.
func (v *Verifier) Ticket(ctx context.Context, token, typ, wantScope string) (Claims, error) {
	if err := checkTicketTyp(typ); err != nil {
		return Claims{}, err
	}
	claims, err := v.Verify(ctx, token, typ, nil)
	if err != nil {
		return Claims{}, err
	}
	if err := checkTicketScope(typ, claims.Scope, wantScope); err != nil {
		return Claims{}, err
	}
	if err := v.consumeTicketJTI(ctx, claims); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

// checkTicketTyp enforces rule 2 (exact typ per operation) on the caller's
// expected kind before any token work: only ks-approval+jwt (the approval
// handoff) and ks-access+jwt (the payment access ticket) are ticket kinds.
// Every other typ — a delivery, event, or result callback token, the
// party-signed ks-party+jwt, an unknown typ, or none — denies with ErrTyp
// (RFC 8725 section 3.11: an approval-shaped claim set under any other typ
// is rejected even under a valid gateway signature).
//
// Parameters: typ is the expected token kind.
// Returns: nil for the two ticket kinds, else an error carrying ErrTyp.
func checkTicketTyp(typ string) error {
	if typ != wire.TypApproval && typ != wire.TypAccess {
		return fmt.Errorf("verify: %w: Ticket accepts %s or %s, got %q",
			ErrTyp, wire.TypApproval, wire.TypAccess, typ)
	}
	return nil
}

// checkTicketScope enforces rule 5: the presented scope must be well-formed
// for the ticket's kind and exactly equal wantScope, the scope of the
// operation the caller is about to perform. The gateway allowlists scope at
// mint; the recipient still compares it fail-closed here. A missing scope
// has already denied inside Verify (it is a required claim of both ticket
// rows); a mismatch, an empty requested operation, or a scope shaped for
// the other ticket kind denies with ErrClaims.
//
// Parameters: typ is the ticket kind; scope is the presented scope claim;
// wantScope is the caller's requested operation scope.
// Returns: nil on an exact, kind-valid match, else an error carrying
// ErrClaims.
func checkTicketScope(typ, scope, wantScope string) error {
	if scope != wantScope || !scopeAllowedForKind(typ, scope) {
		return fmt.Errorf("verify: %w: scope %q does not match the requested %s operation %q",
			ErrClaims, scope, typ, wantScope)
	}
	return nil
}

// scopeAllowedForKind applies the scope shapes of the Recipient
// Verification Rules: referral or export:<study> for an approval handoff,
// listing:<id> for a payment access ticket, and nothing else for either
// kind.
//
// Parameters: typ is the ticket kind; scope is the presented scope claim.
// Returns: true when the scope is well-formed for the kind.
func scopeAllowedForKind(typ, scope string) bool {
	switch typ {
	case wire.TypApproval:
		return scope == "referral" || prefixNonEmpty(scope, "export:")
	case wire.TypAccess:
		return prefixNonEmpty(scope, "listing:")
	default:
		return false
	}
}

// prefixNonEmpty reports whether scope carries the given prefix followed by
// at least one more character, so a bare "export:" or "listing:" never
// counts as a well-formed scope.
//
// Parameters: scope is the presented scope claim; prefix is the required
// leading segment.
// Returns: true when the prefix is present with a non-empty remainder.
func prefixNonEmpty(scope, prefix string) bool {
	return strings.HasPrefix(scope, prefix) && len(scope) > len(prefix)
}

// consumeTicketJTI enforces rule 6, last: the ticket's jti is reserved in
// the ReplayCache under ScopeJTI until exp plus the 60-second skew, so only
// a ticket that passed every earlier rule spends its jti. A live
// reservation denies with ErrReplay (callers map it to HTTP 409); any cache
// error denies, propagating the cache's own error. A ticket that somehow
// reached this point without a jti denies fail-closed with ErrClaims (Verify
// already requires one for both ticket rows).
//
// Parameters: ctx carries caller cancellation into the cache; claims are
// the verified ticket claims.
// Returns: nil when the jti was fresh and is now consumed, else an error
// carrying ErrReplay or the cache error. Fail closed; never panics.
func (v *Verifier) consumeTicketJTI(ctx context.Context, claims Claims) error {
	if claims.JTI == "" {
		return fmt.Errorf("verify: %w: ticket carries no jti", ErrClaims)
	}
	fresh, err := v.replay.Check(ctx, ScopeJTI, claims.JTI, claims.ExpiresAt.Add(clockSkew))
	if err != nil {
		return fmt.Errorf("verify: jti reservation: %w", err)
	}
	if !fresh {
		return fmt.Errorf("verify: %w: jti %q already consumed", ErrReplay, claims.JTI)
	}
	return nil
}
