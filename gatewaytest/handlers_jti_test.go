package gatewaytest

import (
	"net/http"
	"testing"

	"github.com/konsulin-care/gateway-sdk-go/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mintJTI mints a party bearer token whose payload carries the given jti
// claim, for the single-use jti enforcement fakes.
func mintJTI(t *testing.T, jti string) string {
	t.Helper()
	m, err := NewMinter()
	require.NoError(t, err)
	tok, err := m.Mint(wire.TypParty, []byte(`{"jti":"`+jti+`"}`))
	require.NoError(t, err)
	return tok
}

// TestGatewaytestHandlersJTIReplayDenied asserts that with enforcement
// enabled a second request to a non-admin route carrying a bearer token
// with an already-seen jti answers 401 with the GW-ADMIN-004 envelope,
// while the first request is served normally.
func TestGatewaytestHandlersJTIReplayDenied(t *testing.T) {
	g := newTestGateway(t)
	g.EnforceSingleUsePartyJTI()
	authz := "Bearer " + mintJTI(t, "jti-replay-0001")

	status, _, _ := gatewayIssue(t, g, http.MethodGet, "/v1/parties/p1/health", authz, "", nil)
	assert.Equal(t, http.StatusOK, status, "first request with a fresh jti must be served")

	status, _, body := gatewayIssue(t, g, http.MethodGet, "/v1/parties/p1/health", authz, "", nil)
	assert.Equal(t, http.StatusUnauthorized, status, "replayed jti must be denied")
	requireEnvelopeCode(t, body, "GW-ADMIN-004")
}

// TestGatewaytestHandlersJTIDistinctJTIIdempotencyReplay asserts that
// with enforcement enabled, requests carrying distinct jtis with the
// same Idempotency-Key and body are not denied, and the second replays
// the first response byte-identically.
func TestGatewaytestHandlersJTIDistinctJTIIdempotencyReplay(t *testing.T) {
	g := newTestGateway(t)
	g.EnforceSingleUsePartyJTI()
	body := []byte(`{"field":"value"}`)

	statusA, _, respA := gatewayIssue(t, g, http.MethodPost, "/v1/identities/register",
		"Bearer "+mintJTI(t, "jti-idem-0001"), "idem-key-0001", body)
	require.Equal(t, http.StatusOK, statusA)

	statusB, _, respB := gatewayIssue(t, g, http.MethodPost, "/v1/identities/register",
		"Bearer "+mintJTI(t, "jti-idem-0002"), "idem-key-0001", body)
	assert.Equal(t, http.StatusOK, statusB, "distinct jti with a replayed idempotency key must not be denied")
	assert.Equal(t, respA, respB, "second request must replay the first response byte-identically")
}

// TestGatewaytestHandlersJTIEnforcementDisabledByDefault asserts that
// with enforcement disabled (the default), reusing the same bearer jti
// on a non-admin route is not denied.
func TestGatewaytestHandlersJTIEnforcementDisabledByDefault(t *testing.T) {
	g := newTestGateway(t)
	authz := "Bearer " + mintJTI(t, "jti-default-0001")

	status, _, _ := gatewayIssue(t, g, http.MethodGet, "/v1/parties/p1/health", authz, "", nil)
	require.Equal(t, http.StatusOK, status)

	status, _, body := gatewayIssue(t, g, http.MethodGet, "/v1/parties/p1/health", authz, "", nil)
	assert.NotEqual(t, http.StatusUnauthorized, status, "disabled enforcement must not deny jti reuse: %s", body)
	assert.Equal(t, http.StatusOK, status)
}

// TestGatewaytestHandlersJTIUndecodableNotDenied asserts that with
// enforcement enabled, requests without a decodable bearer jti are not
// denied: no Authorization header, a non-bearer scheme, an undecodable
// bearer token, and a decodable token without a jti claim all pass on
// repeated hits.
func TestGatewaytestHandlersJTIUndecodableNotDenied(t *testing.T) {
	g := newTestGateway(t)
	g.EnforceSingleUsePartyJTI()

	cases := []struct {
		name  string
		authz string
	}{
		{"no header", ""},
		{"non-bearer scheme", "Basic dXNlcjpwYXNz"},
		{"undecodable bearer", "Bearer not-a-token"},
		{"empty jti claim", "Bearer " + mintJTI(t, "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Issue the same request twice: neither may be denied.
			for i := 0; i < 2; i++ {
				status, _, body := gatewayIssue(t, g, http.MethodGet,
					"/v1/parties/p1/health", tc.authz, "", nil)
				assert.NotEqual(t, http.StatusUnauthorized, status,
					"request without a decodable jti must not be denied (attempt %d): %s", i+1, body)
				assert.Equal(t, http.StatusOK, status)
			}
		})
	}
}

// TestGatewaytestHandlersJTIEnforcedScriptedStillServed asserts that with
// enforcement enabled, a queued scripted step is still served for a
// request whose jti was already seen — scripted steps bypass the jti
// check — and that once the script queue drains the replay is denied.
func TestGatewaytestHandlersJTIEnforcedScriptedStillServed(t *testing.T) {
	g := newTestGateway(t)
	g.EnforceSingleUsePartyJTI()
	authz := "Bearer " + mintJTI(t, "jti-script-0001")
	const route = "/v1/parties/p1/health"

	// First request records the jti and is served the canned example.
	status, _, _ := gatewayIssue(t, g, http.MethodGet, route, authz, "", nil)
	require.Equal(t, http.StatusOK, status)

	// Queue one scripted 429 step; the replayed jti must still pop it.
	g.Script(http.MethodGet, "/v1/parties/{id}/health", ScriptStep{
		Status: http.StatusTooManyRequests,
		Body:   scriptErrorBody(t, "GW-API-002", "rate limited"),
	})
	status, _, _ = gatewayIssue(t, g, http.MethodGet, route, authz, "", nil)
	assert.Equal(t, http.StatusTooManyRequests, status, "queued scripted step must be served for a replayed jti")

	// Script drained: the next replayed jti is denied by enforcement.
	status, _, body := gatewayIssue(t, g, http.MethodGet, route, authz, "", nil)
	assert.Equal(t, http.StatusUnauthorized, status, "script drained, replayed jti must be denied")
	requireEnvelopeCode(t, body, "GW-ADMIN-004")
}
