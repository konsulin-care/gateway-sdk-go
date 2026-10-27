package conformance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/konsulin-care/gateway-sdk-go/auth"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// negativeWrongSigningKey denies a token signed by a key the party never
// enrolled: read the JWKS once, then probe health with the wrong key.
func negativeWrongSigningKey(ctx context.Context, env *Env) error {
	const name = "wrong-signing-key"
	_, wrong, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return named(name, err)
	}
	now := time.Now().Unix()
	claims, err := claimsNow(env.PartyID, now, now+auth.MaxPartyLifetime)
	if err != nil {
		return named(name, err)
	}
	tok, err := signParty(wrong, wire.TypParty, claims)
	if err != nil {
		return named(name, err)
	}
	if err := readJWKS(ctx, env, name); err != nil {
		return err
	}
	status, body, err := probe(ctx, env, http.MethodGet, partyPath(env, "/health"), tok, "", nil)
	if err != nil {
		return named(name, err)
	}
	return named(name, expectDeny(status, body, http.StatusUnauthorized, "GW-ADMIN-004"))
}

// negativeReplayedEnrollmentToken sends one enrollment twice under
// distinct idempotency keys; the second send must deny GW-PARTY-007.
func negativeReplayedEnrollmentToken(ctx context.Context, env *Env) error {
	const name = "replayed-enrollment-token"
	now := time.Now().Unix()
	claims, err := claimsNow(env.PartyID, now, now+auth.MaxPartyLifetime)
	if err != nil {
		return named(name, err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return named(name, err)
	}
	req, err := auth.BuildEnrollment(auth.EnrollmentInput{
		Claims:          claims,
		EnrollmentToken: env.EnrollmentToken,
	}, key)
	if err != nil {
		return named(name, err)
	}
	path := partyPath(env, "/enroll")
	first, err := auth.NewJti()
	if err != nil {
		return named(name, err)
	}
	second, err := auth.NewJti()
	if err != nil {
		return named(name, err)
	}
	if _, _, err := probe(ctx, env, http.MethodPost, path, req.Proof, first, req.Body); err != nil {
		return named(name, err)
	}
	status, body, err := probe(ctx, env, http.MethodPost, path, req.Proof, second, req.Body)
	if err != nil {
		return named(name, err)
	}
	return named(name, expectDeny(status, body, http.StatusUnauthorized, wire.CodeInvalidEnrollmentToken))
}

// negativeWrongTyp denies both wrong-typ shapes: a ks-approval+jwt on a
// party route, and a token with the typ member omitted entirely.
func negativeWrongTyp(ctx context.Context, env *Env) error {
	const name = "wrong-typ"
	now := time.Now().Unix()
	for _, typ := range []string{wire.TypApproval, ""} {
		claims, err := claimsNow(env.PartyID, now, now+auth.MaxPartyLifetime)
		if err != nil {
			return named(name, err)
		}
		priv, err := probeKey(env)
		if err != nil {
			return named(name, err)
		}
		tok, err := signParty(priv, typ, claims)
		if err != nil {
			return named(name, err)
		}
		status, body, err := probe(ctx, env, http.MethodGet, partyPath(env, "/health"), tok, "", nil)
		if err != nil {
			return named(name, err)
		}
		if err := expectDeny(status, body, http.StatusUnauthorized, "GW-ADMIN-004"); err != nil {
			return named(name, fmt.Errorf("typ %q: %w", typ, err))
		}
	}
	return nil
}

// negativeBodySHA256Mismatch builds a bound enrollment, then re-marshals
// the body so its bytes change while its fields stay identical; the
// proof's body_sha256 no longer matches and the send must deny.
func negativeBodySHA256Mismatch(ctx context.Context, env *Env) error {
	const name = "body-sha256-mismatch"
	now := time.Now().Unix()
	claims, err := claimsNow(env.PartyID, now, now+auth.MaxPartyLifetime)
	if err != nil {
		return named(name, err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return named(name, err)
	}
	req, err := auth.BuildEnrollment(auth.EnrollmentInput{
		Claims:          claims,
		EnrollmentToken: env.EnrollmentToken,
	}, key)
	if err != nil {
		return named(name, err)
	}
	var fields map[string]any
	if err := json.Unmarshal(req.Body, &fields); err != nil {
		return named(name, err)
	}
	mutated, err := json.Marshal(fields)
	if err != nil {
		return named(name, err)
	}
	idem, err := auth.NewJti()
	if err != nil {
		return named(name, err)
	}
	status, body, err := probe(ctx, env, http.MethodPost, partyPath(env, "/enroll"), req.Proof, idem, mutated)
	if err != nil {
		return named(name, err)
	}
	return named(name, expectDeny(status, body, http.StatusUnauthorized, "GW-ADMIN-004"))
}

// negativeExpiredToken denies a structurally hand-crafted token whose
// iat/exp lie in the past (iat 400s old, expired 100s ago).
func negativeExpiredToken(ctx context.Context, env *Env) error {
	const name = "expired-token"
	priv, err := probeKey(env)
	if err != nil {
		return named(name, err)
	}
	now := time.Now().Unix()
	claims, err := claimsNow(env.PartyID, now-400, now-100)
	if err != nil {
		return named(name, err)
	}
	tok, err := signParty(priv, wire.TypParty, claims)
	if err != nil {
		return named(name, err)
	}
	status, body, err := probe(ctx, env, http.MethodGet, partyPath(env, "/health"), tok, "", nil)
	if err != nil {
		return named(name, err)
	}
	return named(name, expectDeny(status, body, http.StatusUnauthorized, "GW-ADMIN-004"))
}

// negativeUnknownKid probes with a kid the party never enrolled, reads
// the JWKS once (the one refetch), then probes again — both deny.
func negativeUnknownKid(ctx context.Context, env *Env) error {
	const name = "unknown-kid"
	_, fresh, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return named(name, err)
	}
	now := time.Now().Unix()
	claims, err := claimsNow(env.PartyID, now, now+auth.MaxPartyLifetime)
	if err != nil {
		return named(name, err)
	}
	tok, err := signParty(fresh, wire.TypParty, claims)
	if err != nil {
		return named(name, err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if attempt == 1 {
			if err := readJWKS(ctx, env, name); err != nil {
				return err
			}
		}
		status, body, err := probe(ctx, env, http.MethodGet, partyPath(env, "/health"), tok, "", nil)
		if err != nil {
			return named(name, err)
		}
		if err := expectDeny(status, body, http.StatusUnauthorized, "GW-ADMIN-004"); err != nil {
			return named(name, fmt.Errorf("attempt %d: %w", attempt+1, err))
		}
	}
	return nil
}

// negativeRevokedParty denies a perfectly valid party token on a party
// route once the party is revoked: 403 GW-PARTY-002.
func negativeRevokedParty(ctx context.Context, env *Env) error {
	const name = "revoked-party"
	tok, err := partyToken(env, wire.TypParty)
	if err != nil {
		return named(name, err)
	}
	status, body, err := probe(ctx, env, http.MethodGet, partyPath(env, "/health"), tok, "", nil)
	if err != nil {
		return named(name, err)
	}
	return named(name, expectDeny(status, body, http.StatusForbidden, "GW-PARTY-002"))
}

// negativeCapabilityDenied enqueues a webhook with a valid party token
// but no webhook:invoke grant: 403 capability_denied.
func negativeCapabilityDenied(ctx context.Context, env *Env) error {
	const name = "capability-denied"
	tok, err := partyToken(env, wire.TypParty)
	if err != nil {
		return named(name, err)
	}
	payload, err := json.Marshal(wire.EnqueueWebhookRequest{
		To: env.PartyID, Service: "conformance", Payload: json.RawMessage(`{}`),
	})
	if err != nil {
		return named(name, err)
	}
	idem, err := auth.NewJti()
	if err != nil {
		return named(name, err)
	}
	status, body, err := probe(ctx, env, http.MethodPost, "/v1/webhooks", tok, idem, payload)
	if err != nil {
		return named(name, err)
	}
	return named(name, expectDeny(status, body, http.StatusForbidden, wire.CodeCapabilityDenied))
}

// negativeIdempotencyReplay requires the same key plus same body to
// replay byte-identically, and the same key plus a different body to
// deny 422 GW-HOOK-008.
func negativeIdempotencyReplay(ctx context.Context, env *Env) error {
	const name = "idempotency-replay"
	tok, err := partyToken(env, wire.TypParty)
	if err != nil {
		return named(name, err)
	}
	first, err := json.Marshal(wire.SyncWebhookRequest{
		To: env.PartyID, Service: "conformance", Payload: json.RawMessage(`{"n":1}`),
	})
	if err != nil {
		return named(name, err)
	}
	conflict, err := json.Marshal(wire.SyncWebhookRequest{
		To: env.PartyID, Service: "conformance", Payload: json.RawMessage(`{"n":2}`),
	})
	if err != nil {
		return named(name, err)
	}
	idem, err := auth.NewJti()
	if err != nil {
		return named(name, err)
	}
	const path = "/v1/webhooks/sync"
	s1, b1, err := probe(ctx, env, http.MethodPost, path, tok, idem, first)
	if err != nil {
		return named(name, err)
	}
	if s1 < 200 || s1 > 299 {
		return named(name, fmt.Errorf("first sync status %d, want 2xx", s1))
	}
	s2, b2, err := probe(ctx, env, http.MethodPost, path, tok, idem, first)
	if err != nil {
		return named(name, err)
	}
	if s2 != s1 || !bytes.Equal(b1, b2) {
		return named(name, fmt.Errorf("replay status %d (want %d) or body not byte-identical", s2, s1))
	}
	s3, b3, err := probe(ctx, env, http.MethodPost, path, tok, idem, conflict)
	if err != nil {
		return named(name, err)
	}
	return named(name, expectDeny(s3, b3, http.StatusUnprocessableEntity, "GW-HOOK-008"))
}
