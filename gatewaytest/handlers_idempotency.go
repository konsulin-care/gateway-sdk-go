package gatewaytest

import (
	"crypto/sha256"
	"net/http"
)

// idemEntry is one Idempotency-Key store row: the request-body hash the
// key was first seen with, the in-flight marker, and the stored 2xx
// response once the first request completed successfully.
type idemEntry struct {
	bodyHash [sha256.Size]byte
	inFlight bool
	status   int
	respBody []byte
}

// serveIdempotent applies the fake's idempotency semantics for one keyed
// request and reports whether it wrote the response:
//   - a key seen with the same body replays the stored 2xx response;
//   - a key seen with a different body answers 422 GW-HOOK-008;
//   - a key whose first request is still in flight answers 409
//     GW-API-002 (retryable per SDK-RETRY-002);
//   - a new key is marked in flight, held at the route's Block gate when
//     one is registered, served the canned example, and — on a 2xx
//     outcome — stored for replay; any other outcome releases the key.
func (g *Gateway) serveIdempotent(w http.ResponseWriter, key routeKey, idemKey string, body []byte) bool {
	hash := sha256.Sum256(body)
	status, respBody, gate, handled := g.reserveKey(idemKey, hash, key)
	if handled {
		writeBody(w, status, respBody)
		return true
	}
	g.waitGate(gate)
	canned, ok := cannedRouteFor(key)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return true
	}
	g.finishKey(idemKey, canned.status, canned.body)
	writeBody(w, canned.status, canned.body)
	return true
}

// reserveKey inspects and reserves the idempotency key under one lock.
// For an already-seen key it returns a served response (handled=true: the
// stored replay, the 409 in-flight conflict, or the 422 body conflict).
// For a fresh key it stores an in-flight entry and returns the route's
// gate (handled=false).
func (g *Gateway) reserveKey(idemKey string, hash [sha256.Size]byte, key routeKey) (status int, respBody []byte, gate *Gate, handled bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e, seen := g.idem[idemKey]; seen {
		switch {
		case e.inFlight:
			return http.StatusConflict,
				errorEnvelopeBytes("GW-API-002", "idempotency key still in progress"),
				nil, true
		case e.bodyHash != hash:
			return http.StatusUnprocessableEntity,
				errorEnvelopeBytes("GW-HOOK-008", "idempotency key reused with a different request body"),
				nil, true
		default:
			return e.status, e.respBody, nil, true
		}
	}
	g.idem[idemKey] = &idemEntry{bodyHash: hash, inFlight: true}
	return 0, nil, g.takeGateLocked(key), false
}

// finishKey closes the in-flight window: a 2xx outcome is stored for
// replay; any other outcome releases the key so it may be retried.
func (g *Gateway) finishKey(idemKey string, status int, body []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, seen := g.idem[idemKey]
	if !seen {
		return
	}
	e.inFlight = false
	if status >= 200 && status <= 299 {
		e.status, e.respBody = status, body
		return
	}
	delete(g.idem, idemKey)
}

// writeBody writes one stored, canned, or scripted response body with its
// status and the fake's JSON content type.
func writeBody(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
