// Package verify is the inbound trust layer: gateway JWKS cache with TTL and
// one rate-limited refetch per unknown kid, per-kind token checks, the six
// Recipient Verification Rules, callback middleware, and the ReplayCache
// interface with an in-memory default.
//
// Allowed imports: standard library, internal/jws, internal/jwk, wire (PRD §7
// dependency rules).
//
// Requirement IDs: SDK-VERIFY-001, SDK-VERIFY-002, SDK-VERIFY-003,
// SDK-VERIFY-004, SDK-VERIFY-C01.
package verify
