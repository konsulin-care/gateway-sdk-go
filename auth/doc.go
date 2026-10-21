// Package auth signs outbound party requests: ks-party+jwt claims, header
// kid = RFC 7638 thumbprint of the public key, fresh jti per attempt, and the
// enrollment proof of possession (body_sha256 over the exact POST bytes).
//
// Allowed imports: standard library, internal/jws, internal/jwk, wire (PRD §7
// dependency rules).
//
// Requirement IDs: SDK-AUTH-001, SDK-AUTH-002, SDK-AUTH-003, SDK-AUTH-C01.
package auth
