// Package envelope seals and opens compact JWE payloads per the gateway's
// normative JWE Envelope: alg ECDH-ES, enc A256GCM over X25519, fresh
// ephemeral epk per message, protected-header kid, Concat KDF (SHA-256).
//
// Allowed imports: standard library (crypto/ecdh, crypto/aes, ...), wire
// (PRD §7 dependency rules).
//
// Requirement IDs: SDK-ENV-001, SDK-ENV-002, SDK-ENV-003, SDK-ENV-C01.
package envelope
