// Package jwk implements JWK and JWKS parsing (RFC 7517) and RFC 7638
// thumbprints on the standard library only. Thumbprints define party key kids
// (never a configured value). Besides signing keys (OKP/Ed25519, EC/P-256,
// selected via SigByKid) it parses JWE recipient keys (OKP/X25519, only with
// use "enc" and alg absent or "ECDH-ES", selected via EncByKid).
//
// Allowed imports: standard library only. Never re-exported; only auth,
// verify, gatewaytest, and envelope (recipient use:enc key selection) may use
// it (PRD §7 dependency rules).
//
// Requirement IDs: SDK-AUTH-C01, SDK-VERIFY-001, SDK-ENV-002.
package jwk
