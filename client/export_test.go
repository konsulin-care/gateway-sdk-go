package client

// This file holds test-only hooks shared by the client package's external
// test suite (client_test): transport doubles, a log capture, a replay-cache
// stub, and read accessors for the unexported Client fields. It compiles
// only under go test.

import (
	"context"
	"crypto"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RoundTripFunc adapts a plain function to http.RoundTripper so tests can
// stub the injected transport.
type RoundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip invokes f (the http.RoundTripper contract).
// Parameters: req — the outgoing request. Returns: the stubbed response.
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// LogEntry is one captured slog record: message plus ordered attributes.
type LogEntry struct {
	// Msg is the record message.
	Msg   string
	attrs map[string]slog.Value
	order []string
}

// Keys returns the attribute keys of the record in capture order.
func (e *LogEntry) Keys() []string {
	return append([]string(nil), e.order...)
}

// Value looks up one attribute by key.
// Parameters: key — the attribute name. Returns: the value and whether the
// key was present.
func (e *LogEntry) Value(key string) (slog.Value, bool) {
	v, ok := e.attrs[key]
	return v, ok
}

// add records one attribute, keeping first-seen key order.
func (e *LogEntry) add(key string, v slog.Value) {
	if _, dup := e.attrs[key]; !dup {
		e.order = append(e.order, key)
	}
	if e.attrs == nil {
		e.attrs = map[string]slog.Value{}
	}
	e.attrs[key] = v
}

// LogCapture is an in-memory slog sink for asserting what the client logs.
type LogCapture struct {
	mu      sync.Mutex
	entries []*LogEntry
}

// NewLogCapture returns a fresh capture with no entries.
func NewLogCapture() *LogCapture {
	return &LogCapture{}
}

// Logger returns an *slog.Logger writing every record into this capture.
func (c *LogCapture) Logger() *slog.Logger {
	return slog.New(&captureHandler{sink: c})
}

// Entries returns the captured records in arrival order.
func (c *LogCapture) Entries() []*LogEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*LogEntry(nil), c.entries...)
}

// add appends one record under the capture lock.
func (c *LogCapture) add(e *LogEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, e)
}

// captureHandler implements slog.Handler, forwarding records to a LogCapture.
type captureHandler struct {
	sink   *LogCapture
	groups []string
	attrs  []slog.Attr
}

// Enabled reports true for every level: the capture never drops records.
func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

// Handle records the message and its attributes into the capture.
// Parameters: rec — the slog record. Returns: nil always.
func (h *captureHandler) Handle(_ context.Context, rec slog.Record) error {
	e := &LogEntry{Msg: rec.Message}
	for _, a := range h.attrs {
		e.add(h.join(a.Key), a.Value)
	}
	rec.Attrs(func(a slog.Attr) bool {
		e.add(h.join(a.Key), a.Value)
		return true
	})
	h.sink.add(e)
	return nil
}

// WithAttrs returns a clone carrying attrs on every following record.
func (h *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &clone
}

// WithGroup returns a clone nesting following keys under name.
func (h *captureHandler) WithGroup(name string) slog.Handler {
	clone := *h
	clone.groups = append(append([]string{}, h.groups...), name)
	return &clone
}

// join prefixes key with the active group names.
func (h *captureHandler) join(key string) string {
	if len(h.groups) == 0 {
		return key
	}
	return strings.Join(h.groups, ".") + "." + key
}

// stubReplayCache is a permissive ReplayCache double: every key is fresh.
type stubReplayCache struct{}

// NewStubReplayCache returns a ReplayCache double that never reports a
// replay and never stores anything.
func NewStubReplayCache() ReplayCache {
	return &stubReplayCache{}
}

// Check reports the reservation fresh without storing anything.
func (s *stubReplayCache) Check(context.Context, string, string, time.Time) (bool, error) {
	return true, nil
}

// Release is a no-op.
func (s *stubReplayCache) Release(context.Context, string, string) error {
	return nil
}

// BaseURLOf returns c's parsed base URL (test hook).
func BaseURLOf(c *Client) *url.URL { return c.baseURL }

// PartyIDOf returns c's configured party id (test hook).
func PartyIDOf(c *Client) string { return c.partyID }

// SignerOf returns c's injected party signer (test hook).
func SignerOf(c *Client) crypto.Signer { return c.signer }

// HTTPClientOf returns c's injected *http.Client (test hook).
func HTTPClientOf(c *Client) *http.Client { return c.httpClient }

// LoggerOf returns c's injected logger (test hook).
func LoggerOf(c *Client) *slog.Logger { return c.logger }

// RetryPolicyOf returns c's configured retry policy (test hook).
func RetryPolicyOf(c *Client) RetryPolicy { return c.retry }

// ReplayCacheOf returns c's injected replay cache (test hook).
func ReplayCacheOf(c *Client) ReplayCache { return c.replay }
