// Package gateway covers the gateway-level public routes: JWKS
// (GET /.well-known/jwks) and Health (GET /health) per PRD §9.6. Thin typed
// wrappers over the client core.
//
// Allowed imports: standard library, client, auth, wire (PRD §7 dependency
// rules).
//
// Requirement IDs: SDK-API-001, SDK-API-002.
package gateway
