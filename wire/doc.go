// Package wire holds the shared wire contract: request/response DTOs, the six
// typ constants, token purposes, the capability catalog, the token-kind table,
// and *Error, the one error type surfaced by every SDK call.
//
// Allowed imports: standard library only — wire imports nothing else in the
// module and nothing outside it (PRD §7 dependency rules).
//
// Requirement IDs: SDK-WIRE-001, SDK-WIRE-002, SDK-WIRE-003.
package wire
