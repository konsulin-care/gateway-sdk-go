// Package client holds the Client core: functional options, transport,
// Idempotency-Key generation stable across retries, bounded retry with a fresh
// signature per attempt, and typed *wire.Error surfacing.
//
// Allowed imports: standard library, wire, auth (PRD §7 dependency rules).
// Route packages build on this client; this package imports none of them.
//
// Requirement IDs: SDK-CLIENT-001, SDK-CLIENT-002, SDK-CLIENT-003,
// SDK-CLIENT-C01, SDK-RETRY-001, SDK-RETRY-002, SDK-RETRY-003, SDK-RETRY-C01.
package client
