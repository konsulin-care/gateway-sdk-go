package gatewaytest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
)

// Gateway is the fake gateway HTTP surface (SDK-TEST-001 extension): an
// httptest server serving one canned example response per §9.6
// route-table row, recording every request, replaying idempotent creates
// by Idempotency-Key, and serving scripted response sequences for retry
// tests. Every path outside the route table (the operator DLQ view,
// auth:provider reference contracts, and — unless the opt-in admin
// fakes are enabled via EnableAdmin — every admin route) answers 404 by
// construction. Safe for concurrent use; zero network beyond the local
// loopback listener.
type Gateway struct {
	server   *httptest.Server
	mu       sync.Mutex
	idem     map[string]*idemEntry
	scripts  map[routeKey][]ScriptStep
	gates    map[routeKey]*Gate
	admin    *adminConfig
	recorded []RecordedRequest
}

// NewGateway starts the fake gateway and returns it ready to use. The
// canned example table is prebuilt from the wire DTOs, so construction
// cannot fail.
//
// Returns: the running fake gateway.
func NewGateway() *Gateway {
	g := &Gateway{
		idem:    make(map[string]*idemEntry),
		scripts: make(map[routeKey][]ScriptStep),
		gates:   make(map[routeKey]*Gate),
	}
	g.server = httptest.NewServer(http.HandlerFunc(g.serveHTTP))
	return g
}

// URL returns the fake gateway's base URL (scheme://host:port), for the
// client's base-URL option. It must only be called on a Gateway returned
// by NewGateway.
func (g *Gateway) URL() string {
	return g.server.URL
}

// Close shuts the fake gateway down. It is safe to call more than once
// and is intended for t.Cleanup.
func (g *Gateway) Close() {
	g.server.Close()
}

// Recorded returns a copy of every request the fake has observed —
// excluded (404) paths included — in arrival order.
func (g *Gateway) Recorded() []RecordedRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]RecordedRequest, len(g.recorded))
	copy(out, g.recorded)
	return out
}

// RecordedRequest is one request observed by the fake gateway. PartyJTI is
// the "jti" claim of the Authorization bearer token's payload, decoded
// WITHOUT signature verification — the recorder only surfaces what a test
// put in the token; typ/claim policy belongs to the verify package.
type RecordedRequest struct {
	// Method is the HTTP method of the request.
	Method string
	// Path is the request URL path (no query).
	Path string
	// Authorization is the verbatim Authorization header value.
	Authorization string
	// IdempotencyKey is the verbatim Idempotency-Key header value.
	IdempotencyKey string
	// PartyJTI is the bearer token's jti claim; "" when the header is
	// absent or the token payload is undecodable.
	PartyJTI string
	// Body is the exact request body bytes.
	Body []byte
}

// serveHTTP records the request, then dispatches it: the opt-in admin
// fake when one matches, 404 outside the route table, then a queued
// scripted step when one exists, then the idempotency store when an
// Idempotency-Key header is present, then the route's canned example.
func (g *Gateway) serveHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "gatewaytest: read body", http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	g.recorded = append(g.recorded, newRecordedRequest(r, body))
	g.mu.Unlock()

	if cfg := g.adminEnabled(); cfg != nil && g.serveAdmin(w, r, body, cfg) {
		return
	}

	key, ok := matchRoute(r.Method, r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if g.serveScripted(w, key) {
		return
	}
	if idemKey := r.Header.Get("Idempotency-Key"); idemKey != "" {
		if g.serveIdempotent(w, key, idemKey, body) {
			return
		}
	}
	g.writeCanned(w, key)
}

// writeCanned serves the route's canned example at its registered status
// with Content-Type application/json. A matched route always has a canned
// entry; a missing one answers 404 (fail closed) rather than panicking.
func (g *Gateway) writeCanned(w http.ResponseWriter, key routeKey) {
	canned, ok := cannedRouteFor(key)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(canned.status)
	_, _ = w.Write(canned.body)
}

// errorEnvelopeBytes marshals the gateway error envelope for one catalog
// code. The marshal cannot fail for these string maps; a defensive
// fallback keeps the fake fail-closed without panicking.
func errorEnvelopeBytes(code, message string) []byte {
	body, err := json.Marshal(map[string]any{
		"error": map[string]string{
			"code":       code,
			"message":    message,
			"request_id": "gatewaytest-fake",
		},
	})
	if err != nil {
		return []byte(`{"error":{"code":"GW-API-003","message":"gatewaytest: envelope","request_id":"gatewaytest-fake"}}`)
	}
	return body
}

// newRecordedRequest captures one observed request; the jti claim is
// decoded from the bearer token payload without verification.
func newRecordedRequest(r *http.Request, body []byte) RecordedRequest {
	authz := r.Header.Get("Authorization")
	return RecordedRequest{
		Method:         r.Method,
		Path:           r.URL.Path,
		Authorization:  authz,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
		PartyJTI:       bearerJTI(authz),
		Body:           body,
	}
}

// bearerJTI extracts the "jti" claim from an "Authorization: Bearer"
// token payload via jws.Parse (structural split, no signature check). It
// returns "" for a missing header, a non-bearer scheme, or an undecodable
// token. Never panics.
func bearerJTI(authz string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(authz, prefix) {
		return ""
	}
	token := strings.TrimSpace(strings.TrimPrefix(authz, prefix))
	_, payload, _, err := jws.Parse([]byte(token))
	if err != nil {
		return ""
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.JTI
}
