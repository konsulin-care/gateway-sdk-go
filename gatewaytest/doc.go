// Package gatewaytest is the offline test kit: golden-vector fixture loaders,
// fake gateway servers on httptest, a token minter with a generated test key,
// and a deterministic ReplayCache. Tests using it run with zero network.
//
// Allowed imports: standard library and public SDK packages (PRD §7
// dependency rules). Nothing except tests and cmd/conformance may import
// gatewaytest.
//
// Requirement IDs: SDK-TEST-001, SDK-TEST-002.
package gatewaytest
