package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Claims are the verified claims of one inbound gateway token. Fields hold
// what the checks enforced; conditional claims (UserRef, PaymentID) are
// empty when the token did not carry them. Unknown claim names are decoded
// away (SDK-WIRE-004): they never deny and never surface here.
type Claims struct {
	// Typ is the exact token kind the token was verified as.
	Typ string
	// Iss is the issuer; always "gateway" after a successful Verify.
	Iss string
	// Sub is the subject claim (sender party, gateway, or caller per the
	// Token Kinds table row).
	Sub string
	// Audience holds the aud claim: after Verify exactly one element,
	// equal to the verifier's self identity.
	Audience []string
	// Scope is the operation scope on approval/access tickets
	// (referral, export:<study>, listing:<id>); empty on other kinds.
	Scope string
	// Purpose is the token purpose claim, verified against the kind's
	// allowed purposes.
	Purpose string
	// JTI is the single-use token id on approval, access, and result
	// tokens; empty on delivery/event tokens (they carry WebhookID).
	JTI string
	// WebhookID is the webhook invocation id on delivery, event, and
	// result tokens.
	WebhookID string
	// UserRef is the conditional user reference on delivery tokens for
	// user-scoped listings; empty when absent.
	UserRef string
	// PaymentID is the conditional payment reference on delivery tokens
	// (the buyer's latest PAID payment); empty when absent.
	PaymentID string
	// BodySHA256 is the base64url (unpadded) SHA-256 claim value over the
	// exact body bytes on delivery/event tokens; empty on other kinds.
	BodySHA256 string
	// IssuedAt is the iat claim as a time (second precision).
	IssuedAt time.Time
	// ExpiresAt is the exp claim as a time (second precision).
	ExpiresAt time.Time
}

// rawClaims is a decoded claims object with every value kept in its raw JSON
// encoding, so a missing claim is distinguishable from a present-but-wrong
// one and each accessor decides the accepted JSON types explicitly.
type rawClaims map[string]json.RawMessage

// parseRawClaims decodes a token payload as a JSON claims object. It fails
// closed on non-object payloads (arrays, strings, null, malformed JSON).
//
// Parameters: payload is the raw token payload bytes.
// Returns: the raw claims and nil, or an error naming the decode failure.
func parseRawClaims(payload []byte) (rawClaims, error) {
	var raw rawClaims
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("claims decode: %w", err)
	}
	if raw == nil {
		return nil, errors.New("claims decode: payload is not a JSON object")
	}
	return raw, nil
}

// str returns the claim as a JSON string. A missing claim, a non-string
// value, or a JSON null all yield ok=false — callers treat that as
// absent-or-invalid, fail closed.
func (c rawClaims) str(name string) (string, bool) {
	v, ok := c[name]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false
	}
	return s, true
}

// seconds returns the claim as a JSON number of seconds since the Unix
// epoch. A missing claim, a fractional value, or a non-number all yield
// ok=false.
func (c rawClaims) seconds(name string) (time.Time, bool) {
	v, ok := c[name]
	if !ok {
		return time.Time{}, false
	}
	var n int64
	if err := json.Unmarshal(v, &n); err != nil {
		return time.Time{}, false
	}
	return time.Unix(n, 0), true
}

// audiences returns the aud claim, which RFC 7519 allows as either a single
// string or an array of strings. Any other shape (number, object, null,
// mixed array, empty array) yields ok=false; a single string is returned as
// a one-element slice.
func (c rawClaims) audiences(name string) ([]string, bool) {
	v, ok := c[name]
	if !ok {
		return nil, false
	}
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return []string{s}, true
	}
	var arr []string
	if err := json.Unmarshal(v, &arr); err != nil || len(arr) == 0 {
		return nil, false
	}
	return arr, true
}

// present reports whether a required claim is present and usable: a
// non-empty string, a number (iat/exp), or a non-empty aud. An empty
// string, null, a wrong-typed value, or absence all count as missing so a
// required-but-empty claim never passes as satisfied.
func (c rawClaims) present(name string) bool {
	if name == "aud" {
		aud, ok := c.audiences(name)
		return ok && aud[0] != ""
	}
	if s, ok := c.str(name); ok {
		return s != ""
	}
	_, ok := c.seconds(name)
	return ok
}

// claims renders the decoded raw values into the exported Claims struct.
// Members that fail to decode are left at their zero value; the required-
// claim and per-kind checks have already denied every unusable token before
// this runs, so this is best-effort shaping, not validation.
func (c rawClaims) claims(typ string) Claims {
	iss, _ := c.str("iss")
	sub, _ := c.str("sub")
	scope, _ := c.str("scope")
	purpose, _ := c.str("purpose")
	jti, _ := c.str("jti")
	webhookID, _ := c.str("webhook_id")
	userRef, _ := c.str("user_ref")
	paymentID, _ := c.str("payment_id")
	bodySHA, _ := c.str("body_sha256")
	aud, _ := c.audiences("aud")
	iat, _ := c.seconds("iat")
	exp, _ := c.seconds("exp")
	return Claims{
		Typ:        typ,
		Iss:        iss,
		Sub:        sub,
		Audience:   aud,
		Scope:      scope,
		Purpose:    purpose,
		JTI:        jti,
		WebhookID:  webhookID,
		UserRef:    userRef,
		PaymentID:  paymentID,
		BodySHA256: bodySHA,
		IssuedAt:   iat,
		ExpiresAt:  exp,
	}
}
