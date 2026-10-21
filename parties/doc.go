// Package parties covers the party lifecycle routes: Enroll
// (POST /v1/parties/{id}/enroll), Rotate (POST /v1/parties/{id}/keys), JWKS
// (GET /v1/parties/{id}/jwks), and Health (GET /v1/parties/{id}/health) per
// PRD §9.6.
//
// Allowed imports: standard library, client, auth, wire (PRD §7 dependency
// rules).
//
// Requirement IDs: SDK-API-001, SDK-API-002.
package parties
