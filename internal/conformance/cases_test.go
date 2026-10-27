package conformance

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/gatewaytest"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// conformancePartyID and conformanceEnrollToken are the party context
// the offline negative probes send; the scripted fake never validates
// them, it answers the scripted or canned responses.
const (
	conformancePartyID     = "01HZYPARTYCONFORMANCE1"
	conformanceEnrollToken = "enroll-token-conformance-001"
)

// The fake routes the negative probes hit. Scripts key on the "{id}"
// route patterns; the probes issue the concrete paths.
const (
	partyHealthPath  = "/v1/parties/{id}/health"
	partyEnrollPath  = "/v1/parties/{id}/enroll"
	webhooksPath     = "/v1/webhooks"
	webhooksSyncPath = "/v1/webhooks/sync"
)

// denyStep builds one scripted gateway error envelope for a negative
// case's expected deny.
func denyStep(t *testing.T, status int, code string) gatewaytest.ScriptStep {
	t.Helper()
	body, err := json.Marshal(map[string]any{"error": map[string]string{
		"code": code, "message": "scripted conformance deny", "request_id": "scripted-deny",
	}})
	require.NoError(t, err, "marshal scripted deny envelope")
	return gatewaytest.ScriptStep{Status: status, Body: body}
}

// negativeEnv builds the conformance env an offline negative case runs
// against a scripted fake gateway.
func negativeEnv(g *gatewaytest.Gateway) *Env {
	return &Env{BaseURL: g.URL(), PartyID: conformancePartyID, EnrollmentToken: conformanceEnrollToken}
}

// scriptDeny queues each negative case's expected deny responses; routes
// not scripted here answer their canned 2xx examples (e.g. the JWKS
// reads the wrong-key and unknown-kid cases perform, and the first
// enrollment send of the replay case).
func scriptDeny(t *testing.T, g *gatewaytest.Gateway, name string) {
	t.Helper()
	switch name {
	case "wrong-signing-key":
		g.Script(http.MethodGet, partyHealthPath, denyStep(t, http.StatusUnauthorized, "GW-ADMIN-004"))
	case "replayed-enrollment-token":
		g.Script(http.MethodPost, partyEnrollPath,
			gatewaytest.ScriptStep{Status: http.StatusOK},
			denyStep(t, http.StatusUnauthorized, wire.CodeInvalidEnrollmentToken))
	case "wrong-typ":
		g.Script(http.MethodGet, partyHealthPath,
			denyStep(t, http.StatusUnauthorized, "GW-ADMIN-004"),
			denyStep(t, http.StatusUnauthorized, "GW-ADMIN-004"))
	case "body-sha256-mismatch":
		g.Script(http.MethodPost, partyEnrollPath, denyStep(t, http.StatusUnauthorized, "GW-ADMIN-004"))
	case "expired-token":
		g.Script(http.MethodGet, partyHealthPath, denyStep(t, http.StatusUnauthorized, "GW-ADMIN-004"))
	case "unknown-kid":
		g.Script(http.MethodGet, partyHealthPath,
			denyStep(t, http.StatusUnauthorized, "GW-ADMIN-004"),
			denyStep(t, http.StatusUnauthorized, "GW-ADMIN-004"))
	case "revoked-party":
		g.Script(http.MethodGet, partyHealthPath, denyStep(t, http.StatusForbidden, "GW-PARTY-002"))
	case "capability-denied":
		g.Script(http.MethodPost, webhooksPath, denyStep(t, http.StatusForbidden, wire.CodeCapabilityDenied))
	case "idempotency-replay":
		// The canned idempotency store already replays the same key plus
		// same body byte-identically and denies the body conflict 422
		// GW-HOOK-008 — no script needed.
	default:
		t.Fatalf("scriptDeny: unknown negative case %q", name)
	}
}

// scriptAccept makes the fake wrongly accept every send of a negative
// case. All cases pass on the canned 2xx examples except
// idempotency-replay, whose canned store would still deny the body
// conflict — three scripted 200s make the target accept it too.
func scriptAccept(g *gatewaytest.Gateway, name string) {
	if name == "idempotency-replay" {
		g.Script(http.MethodPost, webhooksSyncPath,
			gatewaytest.ScriptStep{Status: http.StatusOK},
			gatewaytest.ScriptStep{Status: http.StatusOK},
			gatewaytest.ScriptStep{Status: http.StatusOK})
	}
}

// TestConformanceNegativeCasesAllNamed asserts the registry carries
// exactly the nine SDK-CONF-002 negative case names, that every case
// name is unique and non-empty, and that each negative case reports
// pass when the target returns its expected deny and fail when a
// scripted gatewaytest wrongly accepts.
func TestConformanceNegativeCasesAllNamed(t *testing.T) {
	cases := Registry()

	seen := make(map[string]bool, len(cases))
	negative := make([]string, 0, len(NegativeNames))
	for _, c := range cases {
		require.NotEmpty(t, c.Name, "registry carries an unnamed case")
		require.False(t, seen[c.Name], "duplicate case name %q", c.Name)
		seen[c.Name] = true
		require.NotNil(t, c.Run, "case %q has no run function", c.Name)
		if c.Kind == KindNegative {
			negative = append(negative, c.Name)
		}
	}
	require.Equal(t, NegativeNames, negative,
		"registry must carry exactly the nine SDK-CONF-002 negative cases in order")

	for _, c := range cases {
		if c.Kind != KindNegative {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			t.Run("passes on the expected deny", func(t *testing.T) {
				g := gatewaytest.NewGateway()
				t.Cleanup(g.Close)
				scriptDeny(t, g, c.Name)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				require.NoError(t, c.Run(ctx, negativeEnv(g)))
			})
			t.Run("fails when the target accepts", func(t *testing.T) {
				g := gatewaytest.NewGateway()
				t.Cleanup(g.Close)
				scriptAccept(g, c.Name)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				require.Error(t, c.Run(ctx, negativeEnv(g)))
			})
		})
	}
}

// TestResultCallbackWaitsForInboundDelivery asserts the callback
// receiver records an inbound result delivery and the result-callback
// case passes only after receiving one.
func TestResultCallbackWaitsForInboundDelivery(t *testing.T) {
	cb := NewCallbackReceiver()
	t.Cleanup(cb.Close)
	env := &Env{BaseURL: "http://gateway.test.invalid", Callback: cb}

	// No delivery yet: the case must not pass, however long it waits.
	bounded, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	require.Error(t, runResultCallback(bounded, env),
		"result-callback must fail before any inbound delivery")

	// Deliver one result over plain HTTP with a Bearer result ticket.
	ctx, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cb.URL()+"/v1/results/conformance", strings.NewReader(`{"result":"ok"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ticket-conformance")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "receiver must answer the delivery 204")

	require.NoError(t, runResultCallback(ctx, env),
		"result-callback must pass after the inbound delivery")

	assert.Equal(t, 1, cb.Count())
	ds := cb.Deliveries()
	require.Len(t, ds, 1)
	assert.Equal(t, http.MethodPost, ds[0].Method)
	assert.Equal(t, "/v1/results/conformance", ds[0].Path)
	assert.Equal(t, "Bearer ticket-conformance", ds[0].Authorization)
	assert.Equal(t, `{"result":"ok"}`, string(ds[0].Body))
	assert.False(t, ds[0].ReceivedAt.IsZero())
}
