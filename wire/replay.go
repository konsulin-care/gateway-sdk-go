package wire

import (
	"context"
	"time"
)

// Replay cache scopes: the key spaces a ReplayCache keeps apart so values
// from different scopes never collide.
const (
	// ScopeJTI scopes a replay-cache entry to a token jti.
	ScopeJTI = "jti"
	// ScopeWebhookID scopes a replay-cache entry to a webhook_id.
	ScopeWebhookID = "webhook_id"
	// ScopeNonce scopes a replay-cache entry to a nonce.
	ScopeNonce = "nonce"
)

// ReplayCache atomically deduplicates (scope, key) pairs. Check reserves the
// pair until the until instant: the first Check of a fresh pair is accepted,
// every later Check of the same live pair is a replay. Any error denies.
// Release frees a reservation so a retry after a failed handler is not
// deduped. Implementations must be safe for concurrent use.
type ReplayCache interface {
	// Check atomically reserves the (scope, key) pair until until.
	//
	// Parameters: ctx carries caller cancellation; scope is a Scope*
	// constant; key is the scoped value; until is the reservation deadline.
	// Returns: true when fresh, false on replay, or an error — deny on error.
	Check(ctx context.Context, scope, key string, until time.Time) (bool, error)

	// Release frees the (scope, key) reservation; unreserved pairs are a
	// no-op.
	//
	// Parameters: ctx carries caller cancellation; scope and key as Check.
	// Returns: nil on success or an error.
	Release(ctx context.Context, scope, key string) error
}
