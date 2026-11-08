package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// queryRecorder is a plain httptest handler that records every attempt's
// path and raw query under a mutex and answers with the scripted statuses
// in order (the last repeats). Race-safe.
type queryRecorder struct {
	mu       sync.Mutex
	paths    []string
	rawQuery []string
	statuses []int
}

// ServeHTTP records the request path and raw query, then answers the next
// scripted status (the last status repeats).
func (q *queryRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q.mu.Lock()
	q.paths = append(q.paths, r.URL.Path)
	q.rawQuery = append(q.rawQuery, r.URL.RawQuery)
	status := q.statuses[min(len(q.paths)-1, len(q.statuses)-1)]
	q.mu.Unlock()
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// recorded returns the paths and raw queries recorded so far.
func (q *queryRecorder) recorded() ([]string, []string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]string(nil), q.paths...), append([]string(nil), q.rawQuery...)
}

// newQueryClient builds an auth-public Client pointed at srv with the
// given retry policy. Parameters: t — the test; srv — the test server;
// policy — the retry policy for the client. Returns: the constructed Client.
func newQueryClient(t *testing.T, srv *httptest.Server, policy client.RetryPolicy) *client.Client {
	t.Helper()
	c, err := client.New(
		client.WithBaseURL(srv.URL),
		client.WithInsecureTransport(),
		client.WithHTTPClient(srv.Client()),
		client.WithLogger(client.NewLogCapture().Logger()),
		client.WithRetry(policy),
	)
	require.NoError(t, err, "a minimal client must construct")
	return c
}

// TestDoSendsQueryParametersOnRequestPath covers the Request.Query
// contract: Do with Query set delivers exactly the URL-encoded query
// parameters to the server on the request path, byte for byte.
func TestDoSendsQueryParametersOnRequestPath(t *testing.T) {
	rec := &queryRecorder{statuses: []int{http.StatusOK}}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	c := newQueryClient(t, srv, client.RetryPolicy{MaxAttempts: 1})

	query := url.Values{
		"status": {"open", "closed"},
		"q":      {"a b&c=d"},
	}
	resp, err := c.Do(context.Background(), client.Request{
		Method: http.MethodGet,
		Path:   "/v1/listings",
		Auth:   wire.AuthPublic,
		Query:  query,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	paths, raws := rec.recorded()
	require.Len(t, paths, 1)
	assert.Equal(t, "/v1/listings", paths[0], "the query must ride on the request path")
	assert.Equal(t, query.Encode(), raws[0],
		"the server must receive exactly the URL-encoded query parameters")
	assert.Equal(t, query, mustParseQuery(t, raws[0]),
		"the delivered query must round-trip to the values the caller set")
}

// TestDoWithNilQuerySendsEmptyRawQuery covers the nil-Query contract: a
// Request without Query delivers a request with an empty raw query — no
// stray "?" and no fabricated parameters.
func TestDoWithNilQuerySendsEmptyRawQuery(t *testing.T) {
	rec := &queryRecorder{statuses: []int{http.StatusOK}}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	c := newQueryClient(t, srv, client.RetryPolicy{MaxAttempts: 1})

	resp, err := c.Do(context.Background(), client.Request{
		Method: http.MethodGet,
		Path:   "/v1/listings",
		Auth:   wire.AuthPublic,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	_, raws := rec.recorded()
	require.Len(t, raws, 1)
	assert.Empty(t, raws[0], "a nil Query must deliver an empty raw query")
}

// TestEveryRetryAttemptDeliversSameRawQuery covers the retry contract for
// Query: one Do call that retries (503 then 200) delivers the identical
// raw query string on every attempt.
func TestEveryRetryAttemptDeliversSameRawQuery(t *testing.T) {
	rec := &queryRecorder{statuses: []int{http.StatusServiceUnavailable, http.StatusOK}}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	c := newQueryClient(t, srv, client.RetryPolicy{
		MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
	})

	query := url.Values{"page": {"2"}, "filter": {"a+b c"}}
	resp, err := c.Do(context.Background(), client.Request{
		Method: http.MethodGet,
		Path:   "/v1/listings",
		Auth:   wire.AuthPublic,
		Query:  query,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	_, raws := rec.recorded()
	require.Len(t, raws, 2, "the retryable 503 must cost one more attempt")
	assert.Equal(t, query.Encode(), raws[0], "attempt 1 must carry the encoded query")
	assert.Equal(t, raws[0], raws[1],
		"every retry attempt of one Do call must deliver the same raw query string")
}

// mustParseQuery parses a raw query string, failing the test on error.
// Parameters: t — the test; raw — the raw query to parse. Returns: the
// parsed url.Values.
func mustParseQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(raw)
	require.NoError(t, err, "the delivered raw query must parse")
	return v
}
