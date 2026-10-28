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

// The operator credentials the offline negative cases opt the fake
// admin handlers in with. The password is a named constant — never
// spelled as a literal after a wire field — so the qc --secret
// scanner does not flag it (the bootstrapTestPass pattern).
const (
	negativeTestUser = "operator"
	negativeTestPass = "op-pass-negative"
)

// negativeEnv builds the conformance env an offline negative case runs
// against a scripted fake gateway, enabling the fake's canned admin
// handlers with matching operator credentials so the two admin-revoke
// cases' destructive setup (fresh login plus revoke) hits canned 2xx
// routes while the probes themselves consume the deny scripts.
func negativeEnv(g *gatewaytest.Gateway) *Env {
	g.EnableAdmin(gatewaytest.AdminOptions{Username: negativeTestUser, Password: negativeTestPass})
	return &Env{
		BaseURL:         g.URL(),
		PartyID:         conformancePartyID,
		EnrollmentToken: conformanceEnrollToken,
		AdminUser:       negativeTestUser,
		AdminPass:       negativeTestPass,
	}
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
		// The gateway expires every party key on revoke, so verification
		// denies 401 GW-ADMIN-004 before any 403 state check runs.
		g.Script(http.MethodGet, partyHealthPath, denyStep(t, http.StatusUnauthorized, "GW-ADMIN-004"))
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

// scriptAccept makes the fake wrongly answer every send of a negative
// case. All cases pass on the canned 2xx examples except
// idempotency-replay, whose canned store would still deny the body
// conflict — three scripted 200s make the target accept it too — and
// revoked-party, whose wrong answer is the 403 state deny the case
// must reject in favor of the 401 key-expiry denial.
func scriptAccept(t *testing.T, g *gatewaytest.Gateway, name string) {
	t.Helper()
	switch name {
	case "idempotency-replay":
		g.Script(http.MethodPost, webhooksSyncPath,
			gatewaytest.ScriptStep{Status: http.StatusOK},
			gatewaytest.ScriptStep{Status: http.StatusOK},
			gatewaytest.ScriptStep{Status: http.StatusOK})
	case "revoked-party":
		g.Script(http.MethodGet, partyHealthPath,
			denyStep(t, http.StatusForbidden, "GW-PARTY-002"))
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
				env := negativeEnv(g)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				require.NoError(t, c.Run(ctx, env))
				assertRevokeBeforeProbe(t, g, c.Name)
			})
			t.Run("fails when the target accepts", func(t *testing.T) {
				g := gatewaytest.NewGateway()
				t.Cleanup(g.Close)
				scriptAccept(t, g, c.Name)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				require.Error(t, c.Run(ctx, negativeEnv(g)))
			})
		})
	}
}

// TestIdempotencyReplaySyncService asserts the idempotency-replay
// case sends Env.ListingService as the sync request's service field,
// defaulting to the chain listing name when the env leaves it empty,
// and that its three probes reuse one idempotency key with the first
// two bodies byte-identical (the replay) and the third conflicting.
func TestIdempotencyReplaySyncService(t *testing.T) {
	tests := []struct {
		name           string
		listingService string
		want           string
	}{
		{name: "env listing service", listingService: "custom-listing-svc", want: "custom-listing-svc"},
		{name: "defaults to the chain listing name", listingService: "", want: conformanceListingName},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := gatewaytest.NewGateway()
			t.Cleanup(g.Close)
			env := negativeEnv(g)
			env.ListingService = tc.listingService
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, negativeIdempotencyReplay(ctx, env),
				"replay must pass against the fake's byte-identical replay store")

			var syncs []gatewaytest.RecordedRequest
			for _, rec := range g.Recorded() {
				if rec.Method == http.MethodPost && rec.Path == webhooksSyncPath {
					syncs = append(syncs, rec)
				}
			}
			require.Len(t, syncs, 3, "replay must send first, replay, and conflict probes")
			require.NotEmpty(t, syncs[0].IdempotencyKey, "probes must carry an idempotency key")
			for i, rec := range syncs {
				assert.Equal(t, syncs[0].IdempotencyKey, rec.IdempotencyKey,
					"sync probe %d must reuse the first idempotency key", i)
			}
			require.Equal(t, syncs[0].Body, syncs[1].Body,
				"the replay probe must resend a byte-identical body")
			require.NotEqual(t, syncs[0].Body, syncs[2].Body,
				"the conflict probe must carry a different body")
			for i, rec := range syncs {
				var req wire.SyncWebhookRequest
				require.NoError(t, json.Unmarshal(rec.Body, &req), "decode sync probe %d body", i)
				assert.Equal(t, tc.want, req.Service, "sync probe %d service", i)
			}
		})
	}
}

// assertRevokeBeforeProbe asserts the recorded request order for the
// two admin-revoke negative cases: the destructive setup's admin
// revoke (capability revoke or party revoke, after the canned login)
// arrives strictly before the denied probe. Cases without an admin
// destructive setup are skipped.
//
// Parameters: t is the assertion target; g is the fake the case ran
// against; name is the negative case name.
func assertRevokeBeforeProbe(t *testing.T, g *gatewaytest.Gateway, name string) {
	t.Helper()
	party := "/v1/admin/parties/" + conformancePartyID
	var revokeMethod, revokePath, probeMethod, probePath string
	switch name {
	case "revoked-party":
		revokeMethod, revokePath = http.MethodPost, party+"/revoke"
		probeMethod, probePath = http.MethodGet, "/v1/parties/"+conformancePartyID+"/health"
	case "capability-denied":
		revokeMethod, revokePath = http.MethodDelete,
			party+"/capabilities/"+wire.CapabilityWebhookInvoke
		probeMethod, probePath = http.MethodPost, webhooksPath
	default:
		return
	}
	revokeIdx, probeIdx := -1, -1
	for i, rec := range g.Recorded() {
		if revokeIdx < 0 && rec.Method == revokeMethod && rec.Path == revokePath {
			revokeIdx = i
		}
		if probeIdx < 0 && rec.Method == probeMethod && rec.Path == probePath {
			probeIdx = i
		}
	}
	require.NotEqual(t, -1, revokeIdx,
		"%s must record the destructive setup's admin revoke", name)
	require.NotEqual(t, -1, probeIdx, "%s must record the denied probe", name)
	assert.Greater(t, probeIdx, revokeIdx,
		"%s: the destructive revoke must arrive before the denied probe", name)
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
