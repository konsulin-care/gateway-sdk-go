package verify

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
)

// webhookIDHeader is the transport header the gateway sets beside the
// webhook_id claim on callback deliveries (the contract's dedupe on
// webhook-id: header + webhook_id claim). net/http canonicalizes it to
// "Webhook-Id"; Request.Header.Get is case-insensitive.
const webhookIDHeader = "Webhook-Id"

// claimsContextKey is the private context key the middleware writes and
// ClaimsFromContext reads, so verified claims never collide with other
// context values.
type claimsContextKey struct{}

// ClaimsFromContext returns the verified claims the callback middleware
// stored on the request context, or the zero Claims when the context
// carries none (a request that never passed through Middleware). The
// returned value is a copy; mutating it never affects the middleware.
//
// Parameters: ctx is the request context handed to the wrapped handler.
// Returns: the verified Claims of the token that authorized the request.
func ClaimsFromContext(ctx context.Context) Claims {
	claims, _ := ctx.Value(claimsContextKey{}).(Claims)
	return claims
}

// Middleware wraps next with the callback middleware (SDK-VERIFY-003): it
// requires Authorization: Bearer <token>, buffers the body exactly once
// through http.MaxBytesReader (default 1 MiB), verifies the token of kind
// typ against the verifier, requires a present webhook-id header to equal
// the webhook_id claim, and dedupes the webhook_id through the verifier's
// ReplayCache after verification. Any bearer, verification, header, or
// cache failure denies with 401 before the handler runs; a body over the
// cap denies with 413. A replayed webhook_id answers 200 with an empty
// body without touching the handler (the gateway treats non-429 4xx as
// terminal failure, so a replay must not 401-loop). On success the handler
// runs once with ClaimsFromContext carrying the verified claims and a
// body buffer holding the exact verified bytes. A handler that responds
// 5xx or panics releases its webhook_id reservation so the gateway's
// retry is not deduped; a panic is re-raised after the release.
//
// Parameters: v is the Verifier (must be non-nil, built with NewVerifier);
// typ is the expected token kind (a wire typ constant); opts configure the
// body cap.
// Returns: a func(http.Handler) http.Handler that wraps the callback
// handler with the middleware pipeline.
func Middleware(v *Verifier, typ string, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	cfg := middlewareConfig{maxBodyBytes: defaultMaxBodyBytes}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mw := &middleware{v: v, typ: typ, maxBody: cfg.maxBodyBytes, next: next}
			mw.serve(w, r)
		})
	}
}

// middleware carries one request's pipeline state through the helpers of
// the serve chain.
type middleware struct {
	v       *Verifier
	typ     string
	maxBody int64
	next    http.Handler
}

// serve runs the middleware pipeline in contract order: bearer extraction,
// one-pass body read, verification, webhook-id header match, replay
// reservation, then the handler. Every failure path writes its status and
// returns without touching the handler.
//
// Parameters: w is the response writer; r is the callback request.
func (m *middleware) serve(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok {
		writeDenial(w, http.StatusUnauthorized)
		return
	}
	body, status := m.readBody(w, r)
	if status != 0 {
		writeDenial(w, status)
		return
	}
	claims, err := m.v.Verify(r.Context(), token, m.typ, body)
	if err != nil {
		writeDenial(w, http.StatusUnauthorized)
		return
	}
	if !webhookIDHeaderMatches(r, claims) {
		writeDenial(w, http.StatusUnauthorized)
		return
	}
	fresh, err := m.reserveWebhookID(r.Context(), claims)
	if err != nil {
		writeDenial(w, http.StatusUnauthorized)
		return
	}
	if !fresh {
		w.WriteHeader(http.StatusOK)
		return
	}
	m.call(w, r, claims, body)
}

// bearerToken extracts the credentials of an Authorization header. The
// scheme compare is case-insensitive (RFC 7235); a missing header, a
// scheme other than Bearer, or empty credentials yield ok=false.
//
// Parameters: r is the callback request.
// Returns: the bearer token and true, or false when no bearer credentials
// are present.
func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	if tok := strings.TrimSpace(h[len(prefix):]); tok != "" {
		return tok, true
	}
	return "", false
}

// readBody replaces the request body with an http.MaxBytesReader capped at
// the configured size and reads it exactly once, so verification and the
// handler both see the same bytes and the source stream is never consumed
// twice. A body over the cap yields status 413 (terminal for the gateway,
// a retry can never shrink it); any other read error denies 401 — without
// the exact bytes body_sha256 cannot be verified.
//
// Parameters: w lets MaxBytesReader reset the connection on overflow; r is
// the callback request whose Body is replaced in place.
// Returns: the buffered body bytes and status 0 on success, or nil and the
// denial status.
func (m *middleware) readBody(w http.ResponseWriter, r *http.Request) ([]byte, int) {
	r.Body = http.MaxBytesReader(w, r.Body, m.maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, http.StatusRequestEntityTooLarge
		}
		return nil, http.StatusUnauthorized
	}
	return body, 0
}

// webhookIDHeaderMatches enforces the contract's webhook-id transport
// header: when the header is present it must equal the webhook_id claim,
// so a request whose header and token disagree is rejected before any
// dedupe. An absent header passes — the claim alone carries the id.
//
// Parameters: r is the callback request; claims are the verified claims.
// Returns: true when no header is present or it equals the claim.
func webhookIDHeaderMatches(r *http.Request, claims Claims) bool {
	h := r.Header.Get(webhookIDHeader)
	if h == "" {
		return true
	}
	return h == claims.WebhookID
}

// reserveWebhookID atomically reserves the token's webhook_id in the
// verifier's ReplayCache until the later of the token's exp+60s skew bound
// and now+retention: the gateway re-mints delivery tokens per retry with
// the same webhook_id, so the reservation must outlive exp. Tokens without
// a webhook_id claim reserve nothing and always proceed. Any cache error
// denies — a cache that cannot record must not let a token through.
//
// Parameters: ctx carries caller cancellation into the cache; claims are
// the verified claims.
// Returns: true when the webhook_id is fresh (proceed), false when it is a
// replay, or a cache error.
func (m *middleware) reserveWebhookID(ctx context.Context, claims Claims) (bool, error) {
	if claims.WebhookID == "" {
		return true, nil
	}
	until := claims.ExpiresAt.Add(clockSkew)
	if retentionFloor := m.v.clock().Add(m.v.retention); retentionFloor.After(until) {
		until = retentionFloor
	}
	return m.v.replay.Check(ctx, ScopeWebhookID, claims.WebhookID, until)
}

// call runs the wrapped handler with the verified claims on the context
// and the buffered body as a fresh byte-exact r.Body, recording the
// response status. After the handler returns — or panics — a 5xx status or
// a panic releases the webhook_id reservation so the gateway's retry
// reaches the handler instead of being deduped; a panic is re-raised
// unchanged. The release never inherits the request context's cancellation,
// so a canceled connection cannot strand the reservation.
//
// Parameters: w is the response writer; r is the callback request; claims
// are the verified claims; body is the buffered request body.
func (m *middleware) call(w http.ResponseWriter, r *http.Request, claims Claims, body []byte) {
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
	rr := r.WithContext(ctx)
	rr.Body = io.NopCloser(bytes.NewReader(body))
	rr.ContentLength = int64(len(body))
	release := func() {
		if claims.WebhookID != "" {
			_ = m.v.replay.Release(context.WithoutCancel(ctx), ScopeWebhookID, claims.WebhookID)
		}
	}
	defer func() {
		if p := recover(); p != nil {
			release()
			panic(p)
		}
		if rec.status >= http.StatusInternalServerError {
			release()
		}
	}()
	m.next.ServeHTTP(rec, rr)
}

// writeDenial writes the denial status with the canonical reason phrase
// as the body; the gateway treats every non-429 4xx as a terminal
// failure.
//
// Parameters: w is the response writer; code is the denial status.
func writeDenial(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

// statusRecorder wraps the middleware's ResponseWriter, recording the
// status code the handler wrote (default 200) so the middleware can
// release the reservation after a 5xx. Flush passes through when the
// underlying writer supports it; Unwrap lets http.ResponseController
// reach the original writer.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

// WriteHeader records the first status code written and forwards it; a
// second call is forwarded untouched (net/http ignores it anyway) without
// overwriting the recorded status.
//
// Parameters: code is the status the handler writes.
func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status, r.wrote = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

// Write records an implicit 200 on the first body write and forwards the
// bytes to the underlying writer.
//
// Parameters: b is the response body chunk.
// Returns: the bytes written and any error from the underlying writer.
func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.status, r.wrote = http.StatusOK, true
	}
	return r.ResponseWriter.Write(b)
}

// Flush forwards to the underlying writer when it implements
// http.Flusher, preserving the default ResponseWriter behaviour.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the wrapped ResponseWriter for http.ResponseController.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
