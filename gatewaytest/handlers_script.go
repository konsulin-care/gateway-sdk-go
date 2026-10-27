package gatewaytest

import "net/http"

// ScriptStep is one scripted response served ahead of the canned example.
type ScriptStep struct {
	// Status is the step's HTTP status; 0 serves 200.
	Status int
	// Headers are extra response headers (e.g. Retry-After).
	Headers map[string]string
	// Body is the step's response body; nil serves the route's canned
	// body at Status.
	Body []byte
	// Wait, when non-nil, blocks the handler until the channel is
	// closed or yields a value — lets a test hold a scripted response.
	Wait <-chan struct{}
}

// Gate is a one-shot hold on one route, installed by Block.
type Gate struct {
	// Started receives one buffered value once a keyed request is held
	// in flight at the gate.
	Started chan struct{}
	// Release lets the held request proceed when closed.
	Release chan struct{}
}

// Script queues scripted responses for the route identified by verb and
// path pattern (the path keeps its {id} pattern). Each request to the
// route pops one step in order; when the queue is exhausted the route
// falls back to its canned example. Scripted responses bypass the
// idempotency store, so a retry sequence may reuse one Idempotency-Key
// across attempts.
//
// Parameters: verb and path identify a §9.6 row; steps are appended to
// the route's queue.
func (g *Gateway) Script(verb, path string, steps ...ScriptStep) {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := routeKey{verb, path}
	g.scripts[key] = append(g.scripts[key], steps...)
}

// Block registers a one-shot gate on the route: the next request that
// reaches the route's idempotency store is held in flight — Started
// receives one value once the request is reserved, and the handler blocks
// until the test closes Release. Requests without an Idempotency-Key are
// never gated, and the gate is consumed by the first hold.
//
// Parameters: verb and path identify a §9.6 row.
// Returns: the gate the test waits on and releases.
func (g *Gateway) Block(verb, path string) *Gate {
	gate := &Gate{
		Started: make(chan struct{}, 1),
		Release: make(chan struct{}),
	}
	g.mu.Lock()
	g.gates[routeKey{verb, path}] = gate
	g.mu.Unlock()
	return gate
}

// takeGateLocked returns the gate registered for the route and removes it
// so it holds at most the first reserved keyed request. Callers must hold
// g.mu.
func (g *Gateway) takeGateLocked(key routeKey) *Gate {
	gate, ok := g.gates[key]
	if !ok {
		return nil
	}
	delete(g.gates, key)
	return gate
}

// waitGate holds the current request at the gate: one non-blocking send
// on Started, then a block until Release closes. A nil gate is a no-op.
func (g *Gateway) waitGate(gate *Gate) {
	if gate == nil {
		return
	}
	select {
	case gate.Started <- struct{}{}:
	default:
	}
	<-gate.Release
}

// serveScripted pops and serves one queued step for the route, reporting
// whether a step existed; false falls through to idempotency/canned.
func (g *Gateway) serveScripted(w http.ResponseWriter, key routeKey) bool {
	g.mu.Lock()
	steps := g.scripts[key]
	if len(steps) == 0 {
		g.mu.Unlock()
		return false
	}
	step := steps[0]
	g.scripts[key] = steps[1:]
	g.mu.Unlock()

	if step.Wait != nil {
		<-step.Wait
	}
	status := step.Status
	if status == 0 {
		status = http.StatusOK
	}
	body := step.Body
	if body == nil {
		canned, ok := cannedRouteFor(key)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		body = canned.body
	}
	w.Header().Set("Content-Type", jsonContentType)
	for name, value := range step.Headers {
		w.Header().Set(name, value)
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
	return true
}
