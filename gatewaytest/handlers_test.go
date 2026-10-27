package gatewaytest

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/konsulin-care/gateway-sdk-go/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// httpResult is the outcome of one request issued from a goroutine.
type httpResult struct {
	status int
	header http.Header
	body   []byte
	err    error
}

// newTestGateway starts a fake Gateway cleaned up via t.Cleanup.
func newTestGateway(t *testing.T) *Gateway {
	t.Helper()
	g := NewGateway()
	t.Cleanup(g.Close)
	return g
}

// gatewayIssue issues one request against the fake; authz and idemKey are
// set only when non-empty.
func gatewayIssue(t *testing.T, g *Gateway, method, path, authz, idemKey string, body []byte) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, g.URL()+path, bytes.NewReader(body))
	require.NoError(t, err)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, b
}

// errorEnvelope is the gateway error envelope the fakes write.
type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

// requireEnvelopeCode asserts body decodes to an error envelope carrying
// the catalog code.
func requireEnvelopeCode(t *testing.T, body []byte, code string) {
	t.Helper()
	var env errorEnvelope
	require.NoError(t, json.Unmarshal(body, &env), "body is not an error envelope: %s", body)
	require.NotNil(t, env.Error, "body has no error object: %s", body)
	assert.Equal(t, code, env.Error.Code)
}

// scriptErrorBody builds one scripted error-envelope body.
func scriptErrorBody(t *testing.T, code, message string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"error": map[string]string{
			"code":       code,
			"message":    message,
			"request_id": "gatewaytest-script",
		},
	})
	require.NoError(t, err)
	return b
}

// TestGatewaytestHandlersCoverRouteTable asserts every §9.6 RouteTable row
// has a registered fake handler that serves the row's canned example
// response: registered status, application/json, exact canned bytes.
func TestGatewaytestHandlersCoverRouteTable(t *testing.T) {
	g := newTestGateway(t)
	for _, row := range wire.RouteTable() {
		t.Run(row.Package+"."+row.Method, func(t *testing.T) {
			canned, ok := exampleRoutes[routeKey{row.Verb, row.Path}]
			require.True(t, ok, "no canned example registered for %s %s", row.Verb, row.Path)
			path := strings.ReplaceAll(row.Path, "{id}", "test-id")
			status, header, body := gatewayIssue(t, g, row.Verb, path, "", "", nil)
			assert.Equal(t, canned.status, status, "%s %s", row.Verb, row.Path)
			assert.Equal(t, "application/json", header.Get("Content-Type"))
			assert.Equal(t, canned.body, body, "%s %s served a non-canned body", row.Verb, row.Path)
		})
	}
}

// TestGatewaytestExcludedRoutes404 asserts routes outside the table — the
// operator DLQ view and admin paths — answer 404, never a canned response.
func TestGatewaytestExcludedRoutes404(t *testing.T) {
	g := newTestGateway(t)
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/webhooks/dlq"},
		{http.MethodGet, "/v1/admin/parties"},
		{http.MethodPost, "/v1/admin/parties/p1/keys/rotate"},
		{http.MethodGet, "/v1/admin/operators"},
		{http.MethodPost, "/v1/admin/login"},
	}
	for _, tc := range cases {
		status, _, _ := gatewayIssue(t, g, tc.method, tc.path, "", "", nil)
		assert.Equal(t, http.StatusNotFound, status, "%s %s must be excluded", tc.method, tc.path)
	}
}

// TestGatewaytestIdempotency asserts replay, conflict, and in-flight
// semantics of the fake's Idempotency-Key store.
func TestGatewaytestIdempotency(t *testing.T) {
	body := []byte(`{"listing_id":"listing-1"}`)
	key := routeKey{http.MethodPost, "/v1/payments"}
	canned, ok := exampleRoutes[key]
	require.True(t, ok)

	t.Run("same key and body replays the stored 2xx", func(t *testing.T) {
		g := newTestGateway(t)
		status, _, first := gatewayIssue(t, g, http.MethodPost, "/v1/payments", "", "replay-key", body)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, canned.body, first)
		status, _, second := gatewayIssue(t, g, http.MethodPost, "/v1/payments", "", "replay-key", body)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, canned.body, second, "replay must return the stored 2xx response")
	})

	t.Run("same key different body returns 422 GW-HOOK-008", func(t *testing.T) {
		g := newTestGateway(t)
		status, _, _ := gatewayIssue(t, g, http.MethodPost, "/v1/payments", "", "conflict-key", body)
		require.Equal(t, http.StatusOK, status)
		status, _, conflictBody := gatewayIssue(t, g, http.MethodPost, "/v1/payments", "", "conflict-key", []byte(`{"listing_id":"listing-2"}`))
		assert.Equal(t, http.StatusUnprocessableEntity, status)
		requireEnvelopeCode(t, conflictBody, "GW-HOOK-008")
	})

	t.Run("duplicate while first is in flight returns 409 GW-API-002", func(t *testing.T) {
		g := newTestGateway(t)
		gate := g.Block(http.MethodPost, "/v1/payments")
		req, err := http.NewRequest(http.MethodPost, g.URL()+"/v1/payments", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Idempotency-Key", "inflight-key")
		first := make(chan httpResult, 1)
		go func() {
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				first <- httpResult{err: err}
				return
			}
			b, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			first <- httpResult{status: resp.StatusCode, header: resp.Header, body: b, err: err}
		}()
		<-gate.Started // the first keyed request is now held in flight
		status, _, dupBody := gatewayIssue(t, g, http.MethodPost, "/v1/payments", "", "inflight-key", body)
		require.Equal(t, http.StatusConflict, status)
		requireEnvelopeCode(t, dupBody, "GW-API-002")
		close(gate.Release)
		res := <-first
		require.NoError(t, res.err)
		assert.Equal(t, http.StatusOK, res.status)
		assert.Equal(t, canned.body, res.body)
		status, _, replayBody := gatewayIssue(t, g, http.MethodPost, "/v1/payments", "", "inflight-key", body)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, canned.body, replayBody, "completed key must replay the stored 2xx")
	})
}

// TestGatewaytestScriptedSequence asserts a scripted 409 -> 429 (with
// Retry-After) -> 200 sequence is served in order and the route then falls
// back to its canned example.
func TestGatewaytestScriptedSequence(t *testing.T) {
	g := newTestGateway(t)
	key := routeKey{http.MethodPost, "/v1/webhooks"}
	canned, ok := exampleRoutes[key]
	require.True(t, ok)
	g.Script(http.MethodPost, "/v1/webhooks",
		ScriptStep{Status: http.StatusConflict, Body: scriptErrorBody(t, "GW-API-002", "idempotency key still in progress")},
		ScriptStep{Status: http.StatusTooManyRequests, Headers: map[string]string{"Retry-After": "7"}, Body: scriptErrorBody(t, "GW-RATE-001", "rate limited")},
		ScriptStep{Status: http.StatusOK}, // nil body: canned body at 200
	)

	status, _, body := gatewayIssue(t, g, http.MethodPost, "/v1/webhooks", "", "", nil)
	require.Equal(t, http.StatusConflict, status)
	requireEnvelopeCode(t, body, "GW-API-002")

	status, header, body := gatewayIssue(t, g, http.MethodPost, "/v1/webhooks", "", "", nil)
	require.Equal(t, http.StatusTooManyRequests, status)
	assert.Equal(t, "7", header.Get("Retry-After"))
	requireEnvelopeCode(t, body, "GW-RATE-001")

	status, _, body = gatewayIssue(t, g, http.MethodPost, "/v1/webhooks", "", "", nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, canned.body, body)

	status, header, body = gatewayIssue(t, g, http.MethodPost, "/v1/webhooks", "", "", nil)
	require.Equal(t, canned.status, status, "exhausted script must fall back to the canned response")
	assert.Equal(t, canned.body, body)
	assert.Empty(t, header.Get("Retry-After"))
}

// TestGatewaytestRecorderExposesRequestMetadata asserts the recorder
// surfaces method, path, Authorization, Idempotency-Key, and the party
// token's jti for each observed request.
func TestGatewaytestRecorderExposesRequestMetadata(t *testing.T) {
	g := newTestGateway(t)
	minter, err := NewMinter()
	require.NoError(t, err)
	token, err := minter.Mint(wire.TypParty, []byte(`{"jti":"jti-recorder-1","sub":"party-1"}`))
	require.NoError(t, err)
	authz := "Bearer " + token

	status, _, _ := gatewayIssue(t, g, http.MethodPost, "/v1/payments", authz, "rec-key-1", []byte(`{"listing_id":"listing-1"}`))
	require.Equal(t, http.StatusOK, status)

	recorded := g.Recorded()
	require.Len(t, recorded, 1)
	rec := recorded[0]
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/v1/payments", rec.Path)
	assert.Equal(t, authz, rec.Authorization)
	assert.Equal(t, "rec-key-1", rec.IdempotencyKey)
	assert.Equal(t, "jti-recorder-1", rec.PartyJTI)
}

// TestGatewaytestDoesNotImportClient asserts the package compiles without
// the client package: no file here imports it.
func TestGatewaytestDoesNotImportClient(t *testing.T) {
	const clientImport = "github.com/konsulin-care/gateway-sdk-go/client"
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	seen := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		seen++
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		require.NoError(t, err, "parse %s", name)
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			assert.NotEqual(t, clientImport, path, "%s must not import the client package", name)
		}
	}
	assert.GreaterOrEqual(t, seen, 5, "expected the gatewaytest sources to scan")
}
