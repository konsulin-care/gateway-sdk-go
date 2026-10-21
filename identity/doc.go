// Package identity normalizes identity fields (email lowercase + trim, phone
// E.164) and computes gateway hashfmt HMAC-SHA256 identity hashes (gateway
// ADR-005), plus format validation so malformed hashes never reach the wire.
//
// Allowed imports: standard library, wire (PRD §7 dependency rules).
//
// Requirement IDs: SDK-ID-001, SDK-ID-002, SDK-ID-C01.
package identity
