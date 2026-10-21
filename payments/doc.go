// Package payments covers the payment routes: Create (POST /v1/payments),
// Get (GET /v1/payments/{id}), and AccessToken
// (POST /v1/payments/{id}/access-token) per PRD §9.6.
//
// Allowed imports: standard library, client, auth, wire (PRD §7 dependency
// rules).
//
// Requirement IDs: SDK-API-001, SDK-API-002.
package payments
