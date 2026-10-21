// Package integration holds offline end-to-end tests: enroll -> signed calls
// -> approval -> direct exchange with envelope -> callback through verify
// middleware, all against gatewaytest with zero network. No build tag — these
// tests run on every `go test ./...` and on every PR.
//
// Allowed imports: standard library, public SDK packages, and gatewaytest
// (PRD §7 dependency rules).
//
// Requirement IDs: SDK-TEST-002.
package integration
