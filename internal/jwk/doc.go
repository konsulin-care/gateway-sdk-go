// Package jwk implements JWK and JWKS parsing (RFC 7517) and RFC 7638
// thumbprints on the standard library only. Thumbprints define party key kids
// (never a configured value).
//
// Allowed imports: standard library only. Never re-exported; only auth, verify,
// and gatewaytest may use it (PRD §7 dependency rules).
//
// Requirement IDs: SDK-AUTH-C01, SDK-VERIFY-001, SDK-ENV-002.
package jwk
