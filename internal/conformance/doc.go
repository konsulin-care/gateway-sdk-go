// Package conformance holds the shared conformance cases executed by
// cmd/conformance against a live gateway: positive flows over the QC-chain
// party surface plus the negative cases (wrong key, replay, wrong typ,
// body_sha256 mismatch, expiry, unknown kid, revoked party, capability
// denial, idempotency replay).
//
// Allowed imports: standard library and public SDK packages (PRD §7
// dependency rules).
//
// Requirement IDs: SDK-CONF-001, SDK-CONF-002, SDK-CONF-003, SDK-CONF-C01.
package conformance
