package gatewaytest

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// jsonContentType is the media type of every canned and envelope response.
const jsonContentType = "application/json"

// routeKey identifies one §9.6 route-table row by verb and path pattern.
type routeKey struct {
	verb string
	path string
}

// cannedRoute is a route's canned example: the registered status and the
// exact marshaled body bytes served on every non-scripted, non-replayed
// hit.
type cannedRoute struct {
	status int
	body   []byte
}

// exampleRow is one canned example before marshaling.
type exampleRow struct {
	key    routeKey
	status int
	body   any
}

// routeExamples builds one canned example per §9.6 row in table order,
// from the wire DTOs, so the fake's bodies cannot drift from the SDK
// decoding types. Statuses are the DTO-documented codes (202 on the two
// enqueue/result rows, 200 elsewhere).
func routeExamples() []exampleRow {
	partyJWKS := wire.JWKSResponse{Keys: []wire.JWK{{
		Kty: "OKP", Crv: "Ed25519", Kid: "qc-party-kid-1",
		X:   "cGFydHkta2V5LXg0My1jaGFyYmFzZTY0dXJs",
		Alg: "EdDSA", Use: "sig",
	}}}
	return []exampleRow{
		{routeKey{http.MethodPost, "/v1/parties/{id}/enroll"}, http.StatusOK,
			wire.EnrollPartyResponse{PartyID: "01HZYPARTY0000000000", Kid: "qc-party-kid-1"}},
		{routeKey{http.MethodPost, "/v1/parties/{id}/keys"}, http.StatusOK,
			wire.RotateKeyResponse{Kid: "qc-party-kid-2"}},
		{routeKey{http.MethodGet, "/v1/parties/{id}/jwks"}, http.StatusOK, partyJWKS},
		{routeKey{http.MethodGet, "/v1/parties/{id}/health"}, http.StatusOK,
			wire.PartyHealthResponse{Status: "healthy"}},
		{routeKey{http.MethodPost, "/v1/identities/register"}, http.StatusOK,
			wire.RegisterIdentityResponse{GlobalKey: "01HZYGLOBALKEY000001"}},
		{routeKey{http.MethodPost, "/v1/identities/resolve"}, http.StatusOK,
			wire.ResolveIdentityResponse{Candidates: []wire.IdentityCandidate{{
				GlobalKey: "01HZYGLOBALKEY000001", PartyID: "01HZYPARTY0000000000",
				LocalResourceID: "fixture-patient-001", MatchField: "email",
			}}}},
		{routeKey{http.MethodPost, "/v1/identities/link"}, http.StatusOK,
			wire.LinkIdentityResponse{Linked: true}},
		{routeKey{http.MethodPost, "/v1/approvals"}, http.StatusOK,
			wire.MintApprovalResponse{
				AccessToken: "eyJhbGciOiJFZERTQSIsImtpZCI6InFxLXBhcnR5LWtpZC0xIn0.cGF5bG9hZA.c2ln",
				JTI:         "01HZYAPPROVALJTI000001", ExpiresAt: "2026-12-31T12:00:00Z",
			}},
		{routeKey{http.MethodPost, "/v1/listings"}, http.StatusOK,
			wire.CreateListingResponse{ListingID: "01HZYLISTING000001", State: "active"}},
		{routeKey{http.MethodGet, "/v1/listings"}, http.StatusOK,
			wire.GetListingsResponse{Listings: []wire.ListingRow{{
				ListingID: "01HZYLISTING000001", ProviderPartyID: "01HZXPROVIDER000001",
				Name: "Curated pseudonymized research data", Description: "De-identified cohort extract",
				EndpointURL: "https://clinician.example.com/api/research/access",
				Price:       53200, Currency: "IDR", Invocation: "commodity", PriceScope: "party",
				Metering: "gateway", ProviderTier: "konsulin", ProviderOrgName: "Konsulin Clinic",
			}}}},
		{routeKey{http.MethodPost, "/v1/payments"}, http.StatusOK,
			wire.CreatePaymentResponse{
				PaymentID:        "01HZYPAYMENT000001",
				PaymentURL:       strPtr("https://checkout.example/pay-01hzypayment000001"),
				Amount:           53200,
				Currency:         "IDR",
				ExpiresAt:        strPtr("2026-12-31T23:59:59Z"),
				PaymentSessionID: strPtr("ps-661f87c614802d6c402cd82d"),
				Status:           "PENDING",
			}},
		{routeKey{http.MethodGet, "/v1/payments/{id}"}, http.StatusOK,
			wire.GetPaymentResponse{
				PaymentID: "01HZYPAYMENT000001", Status: "PAID", Amount: 53200, Currency: "IDR",
				PaymentSessionID: strPtr("ps-661f87c614802d6c402cd82d"),
				CreatedAt:        "2026-12-31T23:58:00Z",
			}},
		{routeKey{http.MethodPost, "/v1/payments/{id}/access-token"}, http.StatusOK,
			wire.AccessTokenResponse{
				AccessToken: "eyJhbGciOiJFZERTQSIsImtpZCI6Imd3LWtleS0xIn0.cGF5bG9hZA.c2ln",
				ExpiresAt:   "2026-12-31T12:14:00Z",
			}},
		{routeKey{http.MethodPost, "/v1/webhooks"}, http.StatusAccepted,
			wire.EnqueueWebhookResponse{WebhookID: "01JAV3Q6R7K9X2M4N8P0Q1S5T7"}},
		{routeKey{http.MethodPost, "/v1/webhooks/sync"}, http.StatusOK,
			wire.SyncWebhookResponse{
				StatusCode: 200, Body: `{"status":"healthy"}`,
				ContentType: "application/json", WebhookID: "01JAV3Q6R7K9X2M4N8P0Q1S5T7",
			}},
		{routeKey{http.MethodGet, "/v1/webhooks/{id}/status"}, http.StatusOK,
			wire.WebhookStatusResponse{
				State: "delivered", Attempts: 1,
				NextAttemptAt: "2026-12-31T12:00:00Z", CreatedAt: "2026-12-31T11:59:59Z",
			}},
		{routeKey{http.MethodPost, "/v1/webhooks/{id}/result"}, http.StatusAccepted,
			wire.WebhookResultResponse{Status: "accepted"}},
		{routeKey{http.MethodGet, "/.well-known/jwks"}, http.StatusOK, partyJWKS},
		{routeKey{http.MethodGet, "/health"}, http.StatusOK,
			wire.GatewayHealthResponse{Status: "ok", Version: "1.4.2"}},
	}
}

// exampleRoutes is the canned table keyed by routeKey; routeOrder keeps
// table order for inbound path matching. Built once from routeExamples.
var exampleRoutes, routeOrder = buildExampleRoutes()

// buildExampleRoutes marshals every canned example once, returning the
// keyed table and the ordered keys used for matching.
func buildExampleRoutes() (map[routeKey]cannedRoute, []routeKey) {
	rows := routeExamples()
	table := make(map[routeKey]cannedRoute, len(rows))
	order := make([]routeKey, 0, len(rows))
	for _, row := range rows {
		table[row.key] = cannedRoute{status: row.status, body: marshalExample(row.body)}
		order = append(order, row.key)
	}
	return table, order
}

// marshalExample marshals a canned example DTO. It panics only on a
// developer error — the literal values in routeExamples cannot fail to
// marshal.
func marshalExample(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("gatewaytest: canned example: " + err.Error())
	}
	return b
}

// cannedRouteFor returns the canned response for a matched route.
func cannedRouteFor(key routeKey) (cannedRoute, bool) {
	canned, ok := exampleRoutes[key]
	return canned, ok
}

// strPtr returns a pointer to s for the nullable wire fields in canned
// examples.
func strPtr(s string) *string { return &s }

// matchRoute finds the route-table row matching an inbound verb and path:
// "{id}" pattern segments match exactly one non-empty request segment and
// every other segment must equal the request's. First match in table
// order wins; anything unmatched (admin paths, GET /v1/webhooks/dlq, the
// auth:provider reference contracts) is excluded by construction.
func matchRoute(verb, path string) (routeKey, bool) {
	segs := splitPath(path)
	for _, key := range routeOrder {
		if key.verb == verb && segmentsMatch(splitPath(key.path), segs) {
			return key, true
		}
	}
	return routeKey{}, false
}

// splitPath cuts a URL path into segments ("/a/b" -> [a b], "/" -> nil).
func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// segmentsMatch reports whether request segments satisfy a route pattern
// of the same length.
func segmentsMatch(pattern, segs []string) bool {
	if len(pattern) != len(segs) {
		return false
	}
	for i, ps := range pattern {
		if strings.HasPrefix(ps, "{") && strings.HasSuffix(ps, "}") {
			if segs[i] == "" {
				return false
			}
			continue
		}
		if ps != segs[i] {
			return false
		}
	}
	return true
}
