package verify

import "errors"

// ErrUnknownKid denies a token whose header kid resolves to no signing key in
// the cached gateway JWKS (SDK-VERIFY-001): an unknown kid, an empty kid, or
// a kid that only matches a non-signing entry such as an X25519 use:enc key.
// Callers match it with errors.Is; the JWKS cache emits it after at most one
// rate-limited refetch per window.
var ErrUnknownKid = errors.New("verify: unknown kid")

// ErrTyp denies a token whose protected header typ does not exactly match
// the expected token kind, whose typ header member is missing, or whose alg
// is not allowed for that kind (SDK-VERIFY-002; RFC 8725 section 3.11).
// Callers match it with errors.Is.
var ErrTyp = errors.New("verify: typ mismatch")

// ErrUnsupportedKind denies a token kind this verifier cannot verify at all:
// ks-party+jwt is party-signed and never verifiable against the gateway JWKS
// (decision: Verify refuses it before any signature work). Callers match it
// with errors.Is.
var ErrUnsupportedKind = errors.New("verify: unsupported token kind")

// ErrIssuer denies a token whose iss is not "gateway" (SDK-VERIFY-002).
// Callers match it with errors.Is.
var ErrIssuer = errors.New("verify: issuer is not gateway")

// ErrAudience denies a token whose aud is not exactly this recipient: a
// string or single-element array equal to self passes; a multi-element array
// or any other value denies (SDK-VERIFY-002). Callers match it with errors.Is.
var ErrAudience = errors.New("verify: audience is not this recipient")

// ErrExpired denies a token whose exp lies beyond the 60-second skew window
// (SDK-VERIFY-002). An exp inside the skew still verifies. Callers match it
// with errors.Is.
var ErrExpired = errors.New("verify: token expired beyond the 60s skew")

// ErrClaims denies a token with a missing or malformed required claim per
// its Token Kinds table row, or an iat more than 60 seconds in the future
// (SDK-VERIFY-002). Callers match it with errors.Is.
var ErrClaims = errors.New("verify: required claim missing or invalid")

// ErrPurpose denies a token whose purpose is not allowed for its kind:
// delivery and result are pinned to their exact purpose, event accepts
// exactly the four event purposes, approval/access require a non-empty
// purpose (SDK-VERIFY-002). Callers match it with errors.Is.
var ErrPurpose = errors.New("verify: purpose not allowed for token kind")

// ErrBodyHash denies a delivery or event token whose body_sha256 does not
// equal the base64url SHA-256 of the exact body bytes (constant-time
// compare; SDK-VERIFY-002). Callers match it with errors.Is.
var ErrBodyHash = errors.New("verify: body_sha256 does not match the body")

// ErrSignature denies a token that is not a well-formed compact JWS or whose
// EdDSA signature does not verify under the kid-selected gateway key
// (SDK-VERIFY-002). Callers match it with errors.Is.
var ErrSignature = errors.New("verify: signature verification failed")

// ErrReplay denies a token whose jti or webhook_id was already consumed:
// the ReplayCache reported the key as seen (SDK-VERIFY-003, SDK-VERIFY-004).
// Callers map it to HTTP 409 on the ticket path. Match it with errors.Is.
var ErrReplay = errors.New("verify: replayed token")
