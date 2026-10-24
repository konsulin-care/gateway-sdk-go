package verify

import "errors"

// ErrUnknownKid denies a token whose header kid resolves to no signing key in
// the cached gateway JWKS (SDK-VERIFY-001): an unknown kid, an empty kid, or
// a kid that only matches a non-signing entry such as an X25519 use:enc key.
// Callers match it with errors.Is; the JWKS cache emits it after at most one
// rate-limited refetch per window.
var ErrUnknownKid = errors.New("verify: unknown kid")
