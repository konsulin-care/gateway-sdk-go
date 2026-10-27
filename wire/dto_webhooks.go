package wire

import "encoding/json"

// EnqueueWebhookRequest is the POST /v1/webhooks body: one async
// marketplace invocation against a provider webhook listing.
type EnqueueWebhookRequest struct {
	// To is the provider party (must hold an active webhook listing
	// under Service).
	To string `json:"to"`
	// Service is the listing name; resolution is most-recent-active
	// per (provider, name).
	Service string `json:"service"`
	// UserRef is the end-user peppered hash for user-scoped listings.
	UserRef string `json:"user_ref,omitempty"`
	// Payload is the opaque invocation payload, relayed verbatim;
	// the gateway never parses it.
	Payload json.RawMessage `json:"payload"`
}

// EnqueueWebhookResponse is the 202 body of POST /v1/webhooks.
type EnqueueWebhookResponse struct {
	// WebhookID is the 26-char ULID of the outbox row.
	WebhookID string `json:"webhook_id"`
}

// SyncWebhookRequest is the POST /v1/webhooks/sync body: the inline
// forward twin of EnqueueWebhookRequest.
type SyncWebhookRequest struct {
	// To is the provider party (must hold an active webhook listing
	// under Service).
	To string `json:"to"`
	// Service is the listing name.
	Service string `json:"service"`
	// UserRef is the end-user peppered hash; required for
	// user-scoped listings.
	UserRef string `json:"user_ref,omitempty"`
	// Payload is the opaque invocation payload, relayed verbatim.
	Payload json.RawMessage `json:"payload"`
}

// SyncWebhookResponse is the 200 body of POST /v1/webhooks/sync: the
// upstream response relayed verbatim within the gateway envelope.
type SyncWebhookResponse struct {
	// StatusCode is the upstream HTTP status (numeric).
	StatusCode int `json:"status_code"`
	// Body is the upstream response body as a string.
	Body string `json:"body"`
	// ContentType is the upstream Content-Type.
	ContentType string `json:"content_type"`
	// WebhookID correlates the call with GET status hops.
	WebhookID string `json:"webhook_id"`
}

// WebhookStatusResponse is the 200 body of
// GET /v1/webhooks/{id}/status: the observable delivery state machine.
type WebhookStatusResponse struct {
	// State is "pending", "delivered" or "failed".
	State string `json:"state"`
	// Attempts counts delivery attempts so far.
	Attempts int `json:"attempts"`
	// NextAttemptAt is the scheduled next attempt (RFC 3339).
	NextAttemptAt string `json:"next_attempt_at"`
	// LastError appears only on failures (e.g. "payment_required").
	LastError string `json:"last_error,omitempty"`
	// CreatedAt is the enqueue time (RFC 3339).
	CreatedAt string `json:"created_at"`
}

// WebhookResultRequest is the POST /v1/webhooks/{id}/result body: the
// engine's outcome for an invocation.
type WebhookResultRequest struct {
	// Result is the outcome; missing/empty answers 400.
	Result string `json:"result"`
}

// WebhookResultResponse is the 202 body of POST /v1/webhooks/{id}/result.
type WebhookResultResponse struct {
	// Status is "accepted".
	Status string `json:"status"`
}

// ServiceReceiptBody is the gateway-to-buyer service-receipt push body
// (ks-event+jwt, purpose service-receipt): the provider's answer to a
// metering=provider delivery, verbatim.
type ServiceReceiptBody struct {
	// WebhookID is the originating invocation's id (correlation key).
	WebhookID string `json:"webhook_id"`
	// Status is the provider's HTTP status for the delivery.
	Status int `json:"status"`
	// QuotaRemaining is the provider's X-Quota-Remaining header,
	// relayed verbatim as a string; nil marshals JSON null (the
	// provider sent no such header).
	QuotaRemaining *string `json:"quota_remaining"`
	// Body is the provider's response body, verbatim.
	Body string `json:"body"`
}
