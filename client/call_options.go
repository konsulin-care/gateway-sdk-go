package client

import (
	"net/http"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// Request is one outbound gateway call: method, path relative to the base
// URL (starting with "/"), optional JSON body, the route's auth class.
type Request struct {
	Method string         // HTTP method (e.g. http.MethodPost)
	Path   string         // request path relative to the base URL
	Body   []byte         // request body; nil or empty sends no body
	Auth   wire.AuthClass // AuthParty requires a signer (WithSigner)
	// IdempotencyKey is sent verbatim when non-empty; empty leaves generation
	// to the caller of the typed route methods.
	IdempotencyKey string
}

// Response is one gateway response, body read in full; non-2xx carries the
// wire error envelope a typed route decodes with wire.DecodeError.
type Response struct {
	StatusCode int         // HTTP status of the response
	Header     http.Header // clone of the response headers
	Body       []byte      // the complete response body
}
