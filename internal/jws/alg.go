package jws

// AlgEdDSA is the JWS "alg" header value for Ed25519 signatures (RFC 8037
// section 3). It is the default and only algorithm this SDK signs with, and
// the only algorithm accepted for gateway-signed token kinds.
const AlgEdDSA = "EdDSA"

// Token kind typ values (Token Kinds table, PRD §9.7). internal/jws is a
// stdlib-only leaf and cannot import wire, so the six literals are pinned
// equal to wire's by the tests in this package.
const (
	typParty    = "ks-party+jwt"
	typApproval = "ks-approval+jwt"
	typAccess   = "ks-access+jwt"
	typDelivery = "ks-delivery+jwt"
	typEvent    = "ks-event+jwt"
	typResult   = "ks-result+jwt"
)

// AllowedAlgs returns the JWS "alg" values acceptable for a token kind per
// its Token Kinds table row. All six kinds accept EdDSA: the five
// gateway-signed kinds are EdDSA-only, and the party-signed kind defaults to
// EdDSA as well (ES256 is reachable only through an explicit opt-in at a
// higher layer). Any typ outside the table returns nil — callers must fail
// closed on a nil allow-list (RFC 8725 §3.11).
//
// Parameters: typ is the exact typ header value of the token kind.
// Returns: a fresh slice with the allowed alg values, or nil when typ is not
// one of the six known kinds.
func AllowedAlgs(typ string) []string {
	switch typ {
	case typParty, typApproval, typAccess, typDelivery, typEvent, typResult:
		return []string{AlgEdDSA}
	default:
		return nil
	}
}
