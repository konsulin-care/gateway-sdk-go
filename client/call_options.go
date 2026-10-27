package client

import (
	"net/http"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// Request is one outbound gateway call: method, path relative to the base
// URL (starting with "/"), optional JSON body, the route's auth class, and
// its idempotency marking.
type Request struct {
	Method string         // HTTP method (e.g. http.MethodPost)
	Path   string         // request path relative to the base URL
	Body   []byte         // request body; nil or empty sends no body
	Auth   wire.AuthClass // AuthParty requires a signer (WithSigner)
	// Idempotent marks one logical create (SDK-CLIENT-002, ADR-011): the
	// call carries an Idempotency-Key — the caller's IdempotencyKey when
	// set, otherwise one generated for the call and held stable across
	// every attempt of the same logical create.
	Idempotent bool
	// IdempotencyKey is sent verbatim when non-empty; empty with Idempotent
	// set has Do generate the key for the call.
	IdempotencyKey string
}

// WithIdempotencyKey returns a copy of r marked idempotent with the given
// caller-supplied key (SDK-CLIENT-002, ADR-011). The key is sent verbatim
// on every attempt — the SDK never generates, rewrites, or rotates it —
// and the caller owns the same stability obligations as the SDK does for
// generated keys: one logical create keeps the key, a changed body or a
// terminal 402 means a new call with a new key.
// Parameters: key — the caller's Idempotency-Key, sent unchanged.
// Returns: the modified copy of r (value receiver).
func (r Request) WithIdempotencyKey(key string) Request {
	r.Idempotent = true
	r.IdempotencyKey = key
	return r
}

// Response is one gateway response, body read in full; non-2xx carries the
// wire error envelope a typed route decodes with wire.DecodeError.
type Response struct {
	StatusCode int         // HTTP status of the response
	Header     http.Header // clone of the response headers
	Body       []byte      // the complete response body
}
