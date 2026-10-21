// Package webhooks covers the webhook enqueue/sync/status/result routes:
// Enqueue (POST /v1/webhooks), Sync (POST /v1/webhooks/sync), Status
// (GET /v1/webhooks/{id}/status), and Result (POST /v1/webhooks/{id}/result,
// single-use result ticket) per PRD §9.6. Inbound deliveries are not here —
// they are covered by verify middleware (SDK-VERIFY).
//
// Allowed imports: standard library, client, auth, wire (PRD §7 dependency
// rules).
//
// Requirement IDs: SDK-API-001, SDK-API-002.
package webhooks
