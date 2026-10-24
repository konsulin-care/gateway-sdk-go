package wire

import "net/http"

// retryableStatuses is the SDK-RETRY-002 status set used when a
// response carries no recognised gateway code: the transient
// transport statuses a bare proxy or load balancer may emit without an
// error envelope. A recognised code always wins over the status — the
// catalog disposition is normative.
var retryableStatuses = map[int]bool{
	http.StatusTooManyRequests:    true,
	http.StatusBadGateway:         true,
	http.StatusServiceUnavailable: true,
	http.StatusGatewayTimeout:     true,
}

// Retryable reports whether a gateway response with the given HTTP
// status and catalog error code may be retried with bounded backoff
// (SDK-RETRY-002). Classification follows the Error catalog
// disposition (SDK-RETRY-003): a recognised code is retryable iff its
// disposition is DispositionRetry. An unrecognised or empty code falls
// back to status-based classification (429, 502, 503, 504 retryable,
// everything else terminal) rather than erroring, so a future or
// malformed code still classifies fail-closed. Network errors are the
// client layer's concern and never reach this function.
func Retryable(status int, code string) bool {
	if entry, ok := LookupCode(code); ok {
		return entry.Disposition == DispositionRetry
	}
	return retryableStatuses[status]
}

// RequiresNewIdempotencyKey reports whether a 402 Payment Required
// response demands a fresh Idempotency-Key before any later attempt
// (SDK-RETRY-003, ADR-011): 402 is terminal, the payment must settle
// under a new logical create. The flag is status-based, so even an
// unrecognised 402 code is flagged. Every other status is false and
// keeps the key stable across transport retries (ADR-008,
// SDK-RETRY-001).
func RequiresNewIdempotencyKey(status int, _ string) bool {
	return status == http.StatusPaymentRequired
}
