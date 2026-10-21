// Package jws implements compact JWS encode/verify on the standard library
// only (RFC 7515 / RFC 7518): alg checks, Ed25519 and ES256 signature paths,
// and ES256 DER<->raw R||S conversion. Hand-written; no go-jose / jwx.
//
// Allowed imports: standard library only. Never re-exported; only auth, verify,
// and gatewaytest may use it (PRD §7 dependency rules).
//
// Requirement IDs: SDK-AUTH-001, SDK-AUTH-C01, SDK-VERIFY-001.
package jws
