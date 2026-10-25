package wire

import "net/http"

// AuthClass is the authentication class of a §9.6 route row: how the
// gateway authenticates the caller. Values mirror the Bruno collection
// auth tags (auth:public, auth:party, auth:ticket) that the PRD
// coverage rule is written against.
type AuthClass string

// The three authentication classes on the party-call surface.
const (
	// AuthPublic marks routes callable without a party-authenticated
	// token (enrollment with its proof, public reads, the gateway
	// JWKS/health, and the single-use result ticket route — the
	// ticket is the credential, not a party token).
	AuthPublic AuthClass = "public"
	// AuthParty marks routes requiring a party-authenticated request
	// (a signed ks-party+jwt, or a capability the gateway checks).
	AuthParty AuthClass = "party"
	// AuthTicket marks routes authenticated by a single-use gateway
	// ticket (the webhook result callback, Bruno tag auth:ticket).
	AuthTicket AuthClass = "ticket"
)

// Route is one row of the normative §9.6 route table: the SDK package
// and typed method that implement the row, the HTTP verb and path
// pattern, the gateway auth class, and whether the row requires an
// Idempotency-Key header (SDK-API-001 table data, SDK-API-002).
type Route struct {
	// Package is the SDK package that owns the row's typed method
	// (e.g. "parties").
	Package string
	// Method is the typed method name on Package (e.g. "Enroll").
	Method string
	// Verb is the HTTP method of the route.
	Verb string
	// Path is the URL path pattern; "{id}" marks the path parameter.
	Path string
	// Auth is the gateway authentication class of the route.
	Auth AuthClass
	// IdempotencyRequired reports whether the row requires an
	// Idempotency-Key header (SDK-API-002).
	IdempotencyRequired bool
}

// routeTable is the normative §9.6 route table in table order: the
// complete outbound party-call surface, exactly the 19 party-facing
// rows. Admin routes (per §5, incl. the auth:public operator login),
// GET /v1/webhooks/dlq (auth:admin, outside the /v1/admin prefix), the
// auth:provider reference contracts (inbound to the party, covered by
// SDK-VERIFY middleware), and the admin bootstrap trio are excluded —
// the coverage rule is explicit-exclusion, never path-prefix based.
var routeTable = []Route{
	{Package: "parties", Method: "Enroll", Verb: http.MethodPost, Path: "/v1/parties/{id}/enroll", Auth: AuthPublic, IdempotencyRequired: true},
	{Package: "parties", Method: "Rotate", Verb: http.MethodPost, Path: "/v1/parties/{id}/keys", Auth: AuthParty, IdempotencyRequired: true},
	{Package: "parties", Method: "JWKS", Verb: http.MethodGet, Path: "/v1/parties/{id}/jwks", Auth: AuthPublic},
	{Package: "parties", Method: "Health", Verb: http.MethodGet, Path: "/v1/parties/{id}/health", Auth: AuthParty},
	{Package: "identities", Method: "Register", Verb: http.MethodPost, Path: "/v1/identities/register", Auth: AuthParty, IdempotencyRequired: true},
	{Package: "identities", Method: "Resolve", Verb: http.MethodPost, Path: "/v1/identities/resolve", Auth: AuthParty},
	{Package: "identities", Method: "Link", Verb: http.MethodPost, Path: "/v1/identities/link", Auth: AuthParty, IdempotencyRequired: true},
	{Package: "approvals", Method: "Mint", Verb: http.MethodPost, Path: "/v1/approvals", Auth: AuthParty, IdempotencyRequired: true},
	{Package: "listings", Method: "Create", Verb: http.MethodPost, Path: "/v1/listings", Auth: AuthParty, IdempotencyRequired: true},
	{Package: "listings", Method: "List", Verb: http.MethodGet, Path: "/v1/listings", Auth: AuthPublic},
	{Package: "payments", Method: "Create", Verb: http.MethodPost, Path: "/v1/payments", Auth: AuthParty, IdempotencyRequired: true},
	{Package: "payments", Method: "Get", Verb: http.MethodGet, Path: "/v1/payments/{id}", Auth: AuthParty},
	{Package: "payments", Method: "AccessToken", Verb: http.MethodPost, Path: "/v1/payments/{id}/access-token", Auth: AuthParty, IdempotencyRequired: true},
	{Package: "webhooks", Method: "Enqueue", Verb: http.MethodPost, Path: "/v1/webhooks", Auth: AuthParty, IdempotencyRequired: true},
	{Package: "webhooks", Method: "Sync", Verb: http.MethodPost, Path: "/v1/webhooks/sync", Auth: AuthParty, IdempotencyRequired: true},
	{Package: "webhooks", Method: "Status", Verb: http.MethodGet, Path: "/v1/webhooks/{id}/status", Auth: AuthParty},
	{Package: "webhooks", Method: "Result", Verb: http.MethodPost, Path: "/v1/webhooks/{id}/result", Auth: AuthTicket, IdempotencyRequired: true},
	{Package: "gateway", Method: "JWKS", Verb: http.MethodGet, Path: "/.well-known/jwks", Auth: AuthPublic},
	{Package: "gateway", Method: "Health", Verb: http.MethodGet, Path: "/health", Auth: AuthPublic},
}

// RouteTable returns the normative §9.6 route table — the 19
// party-facing rows in table order (SDK-API-001). Admin routes, the
// operator DLQ view, and the auth:provider reference contracts are
// excluded per the PRD coverage rule. The returned slice is a fresh
// copy; mutating it does not affect the package.
func RouteTable() []Route {
	out := make([]Route, len(routeTable))
	copy(out, routeTable)
	return out
}
