package conformance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// InboundDelivery is one inbound result delivery the callback receiver
// observed: the request method and path, the verbatim Authorization
// header, the buffered body, and the receive time. Secrets beyond the
// Authorization header are never recorded (PRD §8).
type InboundDelivery struct {
	// Method is the HTTP method of the delivery request.
	Method string
	// Path is the delivery request URL path.
	Path string
	// Authorization is the verbatim Authorization header value (the
	// gateway result token as delivered).
	Authorization string
	// Body is the exact delivery body bytes.
	Body []byte
	// ReceivedAt is when the delivery completed.
	ReceivedAt time.Time
}

// CallbackReceiver is the plain-HTTP result-callback receiver the
// result-callback case (SDK-CONF-001) observes: a loopback httptest
// server that records every inbound delivery and answers 2xx so a live
// gateway completes its delivery. It is safe for concurrent use.
type CallbackReceiver struct {
	server     *httptest.Server
	mu         sync.Mutex
	deliveries []InboundDelivery
	notify     chan struct{}
}

// NewCallbackReceiver starts a plain-HTTP callback receiver on a local
// loopback listener. Every inbound request is recorded as a delivery
// and answered 204. Zero network beyond the local listener.
//
// Returns: the ready receiver.
func NewCallbackReceiver() *CallbackReceiver {
	r := &CallbackReceiver{notify: make(chan struct{}, 1)}
	r.server = httptest.NewServer(http.HandlerFunc(r.handle))
	return r
}

// handle records one inbound delivery and answers 204 so the sender
// completes; a bounded read keeps one delivery from holding memory.
func (r *CallbackReceiver) handle(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	d := InboundDelivery{
		Method:        req.Method,
		Path:          req.URL.Path,
		Authorization: req.Header.Get("Authorization"),
		Body:          append([]byte(nil), body...),
		ReceivedAt:    time.Now().UTC(),
	}
	r.mu.Lock()
	r.deliveries = append(r.deliveries, d)
	r.mu.Unlock()
	select {
	case r.notify <- struct{}{}:
	default:
	}
	w.WriteHeader(http.StatusNoContent)
}

// URL returns the receiver's base URL for use as a callback target.
func (r *CallbackReceiver) URL() string {
	return r.server.URL
}

// Deliveries returns a copy of every recorded inbound delivery in
// arrival order.
func (r *CallbackReceiver) Deliveries() []InboundDelivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]InboundDelivery, len(r.deliveries))
	copy(out, r.deliveries)
	return out
}

// Count returns the number of recorded inbound deliveries.
func (r *CallbackReceiver) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.deliveries)
}

// WaitForDelivery blocks until at least min deliveries have been
// recorded and one arrives after the call, or ctx is done. It returns
// nil when the wait satisfied, or the context error.
//
// Parameters: ctx carries the deadline; min is the delivery count the
// receiver must have reached.
// Returns: nil on satisfaction, or the context error.
func (r *CallbackReceiver) WaitForDelivery(ctx context.Context, min int) error {
	for {
		r.mu.Lock()
		n := len(r.deliveries)
		r.mu.Unlock()
		if n >= min {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.notify:
		}
	}
}

// Close shuts the receiver down. Safe to call more than once; intended
// for t.Cleanup.
func (r *CallbackReceiver) Close() {
	r.server.Close()
}

// runResultCallback passes only after the plain-HTTP callback receiver
// records at least one inbound result delivery carrying a POST with a
// Bearer result credential; ctx bounds the wait.
func runResultCallback(ctx context.Context, env *Env) error {
	if env == nil || env.Callback == nil {
		return errors.New("conformance: result-callback: env callback receiver is required")
	}
	if err := env.Callback.WaitForDelivery(ctx, 1); err != nil {
		return fmt.Errorf("conformance: result-callback: no inbound delivery: %w", err)
	}
	ds := env.Callback.Deliveries()
	last := ds[len(ds)-1]
	if last.Method != http.MethodPost {
		return fmt.Errorf("conformance: result-callback: delivery method %q, want POST", last.Method)
	}
	if !strings.HasPrefix(last.Authorization, "Bearer ") || len(last.Authorization) <= len("Bearer ") {
		return errors.New("conformance: result-callback: delivery carries no Bearer result credential")
	}
	return nil
}
