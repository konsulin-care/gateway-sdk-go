package wire_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// wantRoutes is the normative §9.6 route table in table order: all 19
// party-facing rows with verb, path pattern, gateway auth class and
// Idempotency-Key flag (SDK-API-001/002). Auth classes mirror the
// Bruno auth tags (auth:public, auth:party, auth:ticket).
var wantRoutes = []wire.Route{
	{Package: "parties", Method: "Enroll", Verb: http.MethodPost, Path: "/v1/parties/{id}/enroll", Auth: wire.AuthPublic, IdempotencyRequired: true},
	{Package: "parties", Method: "Rotate", Verb: http.MethodPost, Path: "/v1/parties/{id}/keys", Auth: wire.AuthParty, IdempotencyRequired: true},
	{Package: "parties", Method: "JWKS", Verb: http.MethodGet, Path: "/v1/parties/{id}/jwks", Auth: wire.AuthPublic},
	{Package: "parties", Method: "Health", Verb: http.MethodGet, Path: "/v1/parties/{id}/health", Auth: wire.AuthParty},
	{Package: "identities", Method: "Register", Verb: http.MethodPost, Path: "/v1/identities/register", Auth: wire.AuthParty, IdempotencyRequired: true},
	{Package: "identities", Method: "Resolve", Verb: http.MethodPost, Path: "/v1/identities/resolve", Auth: wire.AuthParty},
	{Package: "identities", Method: "Link", Verb: http.MethodPost, Path: "/v1/identities/link", Auth: wire.AuthParty, IdempotencyRequired: true},
	{Package: "approvals", Method: "Mint", Verb: http.MethodPost, Path: "/v1/approvals", Auth: wire.AuthParty, IdempotencyRequired: true},
	{Package: "listings", Method: "Create", Verb: http.MethodPost, Path: "/v1/listings", Auth: wire.AuthParty, IdempotencyRequired: true},
	{Package: "listings", Method: "List", Verb: http.MethodGet, Path: "/v1/listings", Auth: wire.AuthPublic},
	{Package: "payments", Method: "Create", Verb: http.MethodPost, Path: "/v1/payments", Auth: wire.AuthParty, IdempotencyRequired: true},
	{Package: "payments", Method: "Get", Verb: http.MethodGet, Path: "/v1/payments/{id}", Auth: wire.AuthParty},
	{Package: "payments", Method: "AccessToken", Verb: http.MethodPost, Path: "/v1/payments/{id}/access-token", Auth: wire.AuthParty, IdempotencyRequired: true},
	{Package: "webhooks", Method: "Enqueue", Verb: http.MethodPost, Path: "/v1/webhooks", Auth: wire.AuthParty, IdempotencyRequired: true},
	{Package: "webhooks", Method: "Sync", Verb: http.MethodPost, Path: "/v1/webhooks/sync", Auth: wire.AuthParty, IdempotencyRequired: true},
	{Package: "webhooks", Method: "Status", Verb: http.MethodGet, Path: "/v1/webhooks/{id}/status", Auth: wire.AuthParty},
	{Package: "webhooks", Method: "Result", Verb: http.MethodPost, Path: "/v1/webhooks/{id}/result", Auth: wire.AuthTicket, IdempotencyRequired: true},
	{Package: "gateway", Method: "JWKS", Verb: http.MethodGet, Path: "/.well-known/jwks", Auth: wire.AuthPublic},
	{Package: "gateway", Method: "Health", Verb: http.MethodGet, Path: "/health", Auth: wire.AuthPublic},
}

// TestRouteTableIsNormativeNineteenRows asserts RouteTable returns
// exactly the 19 §9.6 rows in table order, each with its verb, path
// pattern, auth class and idempotency-required flag (SDK-API-001).
func TestRouteTableIsNormativeNineteenRows(t *testing.T) {
	got := wire.RouteTable()
	require.Len(t, got, 19, "the §9.6 table has exactly 19 party-facing rows")
	assert.Equal(t, wantRoutes, got, "RouteTable() must equal the normative §9.6 rows")
}

// TestRouteTableExcludesNonClientRoutes asserts the coverage rule's
// explicit exclusions: no admin route (any /v1/admin path, including
// the auth:public operator login), no GET /v1/webhooks/dlq operator
// view, and no auth:provider reference contract (those are inbound to
// the party and covered by SDK-VERIFY) (SDK-API-001).
func TestRouteTableExcludesNonClientRoutes(t *testing.T) {
	for _, r := range wire.RouteTable() {
		path := strings.ToLower(r.Path)
		assert.NotContains(t, path, "admin",
			"admin route leaked into RouteTable: %s %s", r.Verb, r.Path)
		assert.False(t, r.Verb == http.MethodGet && r.Path == "/v1/webhooks/dlq",
			"operator DLQ view leaked into RouteTable: %s %s", r.Verb, r.Path)
		assert.NotContains(t, path, "dlq",
			"DLQ route leaked into RouteTable: %s %s", r.Verb, r.Path)
		assert.NotEqual(t, "provider", string(r.Auth),
			"auth:provider reference contract leaked into RouteTable: %s %s", r.Verb, r.Path)
		assert.Contains(t, []wire.AuthClass{wire.AuthPublic, wire.AuthParty, wire.AuthTicket},
			r.Auth, "unknown auth class on %s %s", r.Verb, r.Path)
	}
}

// TestRouteTableReturnsFreshSlice asserts the returned slice is a
// copy: mutating it (row or length) must not change a subsequent
// RouteTable() result.
func TestRouteTableReturnsFreshSlice(t *testing.T) {
	first := wire.RouteTable()
	require.Len(t, first, 19)

	first[0].Verb = http.MethodDelete
	first[0].Path = "/mutated"
	first[0].IdempotencyRequired = false
	grown := append(first, wire.Route{
		Package: "admin", Method: "Login", Verb: http.MethodPost,
		Path: "/v1/admin/auth/login", Auth: wire.AuthPublic,
	})
	require.Len(t, grown, 20, "the append must grow only the local copy")

	second := wire.RouteTable()
	assert.Equal(t, wantRoutes, second,
		"mutating a RouteTable() result must not change later calls")
	assert.Len(t, second, 19, "append to a RouteTable() result must not grow the table")
}
