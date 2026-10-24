package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// jtiEntropyBytes is the randomness behind every minted jti: 128 bits from
// crypto/rand, base64url (no padding) encoded — 22 characters.
const jtiEntropyBytes = 16

// MaxPartyLifetime is the maximum lifetime of a ks-party+jwt token in
// seconds: exp − iat MUST NOT exceed 300 s (SDK-AUTH-001). The bound is
// inclusive — exp exactly iat+300 is valid, matching the golden ks-party
// fixture.
const MaxPartyLifetime = 300

// PartyClaims are the claims of an outbound ks-party+jwt request (Token
// Kinds table row: iss, aud, iat, exp, jti). Field order is the JSON marshal
// order, chosen so identical claims always serialize byte-exactly — the
// SDK-AUTH-C01 golden reproduction depends on it.
type PartyClaims struct {
	// Aud is the audience; "gateway" for gateway requests.
	Aud string `json:"aud"`
	// Exp is the expiry (Unix seconds), at most Iat + MaxPartyLifetime.
	Exp int64 `json:"exp"`
	// Iat is the issued-at time (Unix seconds).
	Iat int64 `json:"iat"`
	// Iss is the issuer: the party_id of the signing party.
	Iss string `json:"iss"`
	// Jti is the single-use token id. The gateway rejects a replayed jti;
	// callers mint a fresh one per attempt (SDK-AUTH-003).
	Jti string `json:"jti"`
}

// NewJti mints a fresh single-use jti for one signing attempt
// (SDK-AUTH-003). Every attempt — including a retry of one logical request —
// must carry a jti no earlier attempt has used; the gateway's replay store
// rejects a repeated one. Ids are jtiEntropyBytes cryptographically random
// bytes encoded base64url without padding, so they carry no clock, counter,
// or caller state and two calls never yield the same value in practice.
//
// Returns: the fresh jti and nil, or an error if the system randomness
// source fails. Never panics.
func NewJti() (string, error) {
	var b [jtiEntropyBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("auth: fresh jti: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Validate checks the SDK-AUTH-001 claim constraints: iss, aud, and jti
// non-empty, iat positive, exp strictly after iat, and exp − iat at most
// MaxPartyLifetime. It is structural only and never reads the wall clock,
// so fixtures with fixed timestamps validate; iat freshness is the
// gateway's check.
//
// Returns: nil when the claims are signable, or an error naming the violated
// constraint. Never panics.
func (c PartyClaims) Validate() error {
	if c.Iss == "" {
		return fmt.Errorf("auth: party claims: iss is required")
	}
	if c.Aud == "" {
		return fmt.Errorf("auth: party claims: aud is required")
	}
	if c.Jti == "" {
		return fmt.Errorf("auth: party claims: jti is required")
	}
	if c.Iat <= 0 {
		return fmt.Errorf("auth: party claims: iat must be positive, got %d", c.Iat)
	}
	if c.Exp <= c.Iat {
		return fmt.Errorf("auth: party claims: exp %d must be after iat %d", c.Exp, c.Iat)
	}
	if c.Exp-c.Iat > MaxPartyLifetime {
		return fmt.Errorf("auth: party claims: exp−iat is %ds, maximum is %ds",
			c.Exp-c.Iat, MaxPartyLifetime)
	}
	return nil
}
