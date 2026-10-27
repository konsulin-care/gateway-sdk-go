package client_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/auth"
	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// newPartyKey returns a fresh Ed25519 key pair for party-signing tests.
// Returns: the public and private halves; fails the test if entropy fails.
func newPartyKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "test key generation must not fail")
	return pub, priv
}

// stubResponse builds an *http.Response for RoundTripFunc doubles.
// Parameters: req — the request being answered; status — HTTP status;
// header — response headers (nil means empty); body — the body text.
// Returns: a response with a readable body.
func stubResponse(req *http.Request, status int, header http.Header, body string) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

// TestClientZeroOptionsFailsConstruction covers SDK-CLIENT-C01: a zero-option
// construction fails with an error and a nil Client — no silent defaults.
func TestClientZeroOptionsFailsConstruction(t *testing.T) {
	c, err := client.New()
	require.Error(t, err, "zero options must fail construction")
	require.Nil(t, c, "a failed construction must return a nil Client")
}

// TestNewWithoutBaseURLFailsConstruction asserts WithBaseURL is the required
// option: any New call without it errors even when other options are valid.
func TestNewWithoutBaseURLFailsConstruction(t *testing.T) {
	_, priv := newPartyKey(t)
	c, err := client.New(
		client.WithSigner("party-1", priv),
		client.WithLogger(client.NewLogCapture().Logger()),
	)
	require.Error(t, err, "New without WithBaseURL must fail")
	require.Nil(t, c)
}

// TestNewRejectsInvalidOptionValues asserts an invalid option value (nil
// signer, nil HTTP client, nil logger, malformed URL) fails construction
// instead of being silently ignored (SDK-CLIENT-001 deny expectation).
func TestNewRejectsInvalidOptionValues(t *testing.T) {
	_, priv := newPartyKey(t)

	cases := []struct {
		name string
		opts []client.Option
	}{
		{"nil signer", []client.Option{
			client.WithBaseURL("https://gw.example"), client.WithSigner("party-1", nil)}},
		{"nil http client", []client.Option{
			client.WithBaseURL("https://gw.example"), client.WithHTTPClient(nil)}},
		{"nil logger", []client.Option{
			client.WithBaseURL("https://gw.example"), client.WithLogger(nil)}},
		{"malformed url", []client.Option{
			client.WithBaseURL("://not-a-url"), client.WithSigner("party-1", priv)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := client.New(tc.opts...)
			require.Error(t, err, "invalid option value must fail New")
			require.Nil(t, c)
		})
	}
}

// TestClientEveryOptionAppliedWithContext covers SDK-CLIENT-001: a fully
// configured client records every option and issues the context-bound call
// through the injected *http.Client (proving test for the checklist item).
func TestClientEveryOptionAppliedWithContext(t *testing.T) {
	_, priv := newPartyKey(t)
	capture := client.NewLogCapture()
	logger := capture.Logger()

	var seen *http.Request
	transport := client.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = r
		return stubResponse(r, http.StatusOK,
			http.Header{"X-Request-Id": []string{"req_opt1"}}, `{"ok":true}`), nil
	})
	hc := &http.Client{Transport: transport}
	replay := client.NewStubReplayCache()
	retry := client.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond}

	c, err := client.New(
		client.WithBaseURL("https://gw.example"),
		client.WithSigner("party-1", priv),
		client.WithHTTPClient(hc),
		client.WithInsecureTransport(),
		client.WithReplayCache(replay),
		client.WithLogger(logger),
		client.WithRetry(retry),
	)
	require.NoError(t, err, "every option with a valid value must construct")
	require.NotNil(t, c)

	assert.Equal(t, "gw.example", client.BaseURLOf(c).Host)
	assert.Equal(t, "party-1", client.PartyIDOf(c))
	assert.Equal(t, priv, client.SignerOf(c))
	assert.Equal(t, hc, client.HTTPClientOf(c))
	assert.Equal(t, logger, client.LoggerOf(c))
	assert.Equal(t, retry, client.RetryPolicyOf(c))
	assert.Equal(t, replay, client.ReplayCacheOf(c))

	resp, err := c.Do(context.Background(), client.Request{
		Method:         http.MethodPost,
		Path:           "/v1/things",
		Body:           []byte(`{"a":1}`),
		Auth:           wire.AuthParty,
		IdempotencyKey: "idem-42",
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.NotNil(t, seen, "the injected http.Client must have issued the request")
	assert.Equal(t, http.MethodPost, seen.Method)
	assert.Equal(t, "/v1/things", seen.URL.Path)
	assert.Equal(t, "idem-42", seen.Header.Get("Idempotency-Key"))
	assert.Equal(t, "application/json", seen.Header.Get("Content-Type"))
	assert.True(t, strings.HasPrefix(seen.Header.Get("Authorization"), "Bearer "),
		"party-auth request must carry the signed token")
}

// TestPartyAuthHeaderCarriesSignedGatewayToken asserts the Authorization
// header of a party-auth request is a ks-party+jwt signed by the injected
// signer with iss = the party id and aud = gateway, verified against the
// signer's public key with stdlib Ed25519.
func TestPartyAuthHeaderCarriesSignedGatewayToken(t *testing.T) {
	pub, priv := newPartyKey(t)

	var seen *http.Request
	transport := client.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = r
		return stubResponse(r, http.StatusOK, nil, `{}`), nil
	})
	c, err := client.New(
		client.WithBaseURL("https://gw.example"),
		client.WithSigner("party-123", priv),
		client.WithHTTPClient(&http.Client{Transport: transport}),
		client.WithLogger(client.NewLogCapture().Logger()),
	)
	require.NoError(t, err)

	_, err = c.Do(context.Background(), client.Request{
		Method: http.MethodGet,
		Path:   "/v1/health",
		Auth:   wire.AuthParty,
	})
	require.NoError(t, err)
	require.NotNil(t, seen)

	header := seen.Header.Get("Authorization")
	require.True(t, strings.HasPrefix(header, "Bearer "), "want Bearer scheme, got %q", header)
	token := strings.TrimPrefix(header, "Bearer ")
	segments := strings.Split(token, ".")
	require.Len(t, segments, 3, "compact JWS must have three segments")

	decode := func(seg string) []byte {
		b, decErr := base64.RawURLEncoding.DecodeString(seg)
		require.NoError(t, decErr, "JWS segments must be base64url")
		return b
	}
	var jwsHeader struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	require.NoError(t, json.Unmarshal(decode(segments[0]), &jwsHeader))
	require.Equal(t, "EdDSA", jwsHeader.Alg)
	require.Equal(t, wire.TypParty, jwsHeader.Typ, "exact typ per Token Kinds")

	signingInput := []byte(segments[0] + "." + segments[1])
	require.True(t, ed25519.Verify(pub, signingInput, decode(segments[2])),
		"the token must verify against the injected signer's public key")

	var claims auth.PartyClaims
	require.NoError(t, json.Unmarshal(decode(segments[1]), &claims))
	assert.Equal(t, "party-123", claims.Iss, "iss must be the party id")
	assert.Equal(t, "gateway", claims.Aud, "aud must be the gateway")
	require.NotEmpty(t, claims.Jti, "every attempt signs a fresh jti")
	assert.Positive(t, claims.Iat)
	assert.LessOrEqual(t, claims.Exp-claims.Iat, int64(auth.MaxPartyLifetime))
}

// TestDoLogsMethodPathStatusRequestID asserts the injected slog logger
// records method, path, status and request_id — and nothing else: no bodies,
// no tokens, no keys (PRD §8).
func TestDoLogsMethodPathStatusRequestID(t *testing.T) {
	_, priv := newPartyKey(t)
	capture := client.NewLogCapture()
	transport := client.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		header := http.Header{}
		header.Set("X-Request-Id", "req_log_9")
		return stubResponse(r, http.StatusOK, header, `{"payload":"must-not-be-logged"}`), nil
	})
	c, err := client.New(
		client.WithBaseURL("https://gw.example"),
		client.WithSigner("party-1", priv),
		client.WithHTTPClient(&http.Client{Transport: transport}),
		client.WithLogger(capture.Logger()),
	)
	require.NoError(t, err)

	_, err = c.Do(context.Background(), client.Request{
		Method: http.MethodGet,
		Path:   "/v1/health",
		Auth:   wire.AuthParty,
	})
	require.NoError(t, err)

	entries := capture.Entries()
	require.Len(t, entries, 1, "exactly one response record must be logged")
	entry := entries[0]
	require.Equal(t, "gateway response", entry.Msg)
	require.ElementsMatch(t, []string{"method", "path", "status", "request_id"}, entry.Keys(),
		"the record carries exactly method, path, status and request_id")

	method, ok := entry.Value("method")
	require.True(t, ok)
	assert.Equal(t, "GET", method.String())
	path, ok := entry.Value("path")
	require.True(t, ok)
	assert.Equal(t, "/v1/health", path.String())
	status, ok := entry.Value("status")
	require.True(t, ok)
	require.Equal(t, slog.KindInt64, status.Kind())
	assert.Equal(t, int64(http.StatusOK), status.Int64())
	reqID, ok := entry.Value("request_id")
	require.True(t, ok)
	assert.Equal(t, "req_log_9", reqID.String())

	joined := entry.Msg
	for _, k := range entry.Keys() {
		v, _ := entry.Value(k)
		joined += " " + v.String()
	}
	assert.NotContains(t, joined, "must-not-be-logged", "bodies must never be logged")
	assert.NotContains(t, joined, "Bearer", "tokens must never be logged")
}

// TestCancelledContextAbortsCall asserts a cancelled context aborts the call
// with an error matching context.Canceled, not a silent success.
func TestCancelledContextAbortsCall(t *testing.T) {
	transport := client.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	c, err := client.New(
		client.WithBaseURL("https://gw.example"),
		client.WithHTTPClient(&http.Client{Transport: transport}),
		client.WithLogger(client.NewLogCapture().Logger()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resp, err := c.Do(ctx, client.Request{Method: http.MethodGet, Path: "/v1/health", Auth: wire.AuthPublic})
	require.Error(t, err, "a cancelled context must abort the call")
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestHTTPBaseURLWithoutInsecureTransportFails asserts the transport guard:
// an http base URL fails construction without WithInsecureTransport, while
// https constructs without it.
func TestHTTPBaseURLWithoutInsecureTransportFails(t *testing.T) {
	c, err := client.New(client.WithBaseURL("http://gw.example"))
	require.Error(t, err, "http without WithInsecureTransport must fail")
	require.Nil(t, c)

	// even loopback http needs the explicit opt-in
	c, err = client.New(client.WithBaseURL("http://127.0.0.1:8080"))
	require.Error(t, err, "http without the opt-in must fail even on loopback")
	require.Nil(t, c)

	c, err = client.New(client.WithBaseURL("https://gw.example"))
	require.NoError(t, err, "https is always allowed")
	require.NotNil(t, c)
}

// TestWithInsecureTransportLoopbackOnly asserts WithInsecureTransport
// accepts http for 127.0.0.1, ::1 and localhost, and rejects http for any
// other host (fail-closed transport guard).
func TestWithInsecureTransportLoopbackOnly(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1:8080",
		"http://[::1]:8443",
		"http://localhost:9000",
	} {
		c, err := client.New(client.WithBaseURL(raw), client.WithInsecureTransport())
		require.NoError(t, err, "loopback host %s must be accepted", raw)
		require.NotNil(t, c)
	}

	for _, raw := range []string{
		"http://gw.example",
		"http://10.0.0.1:8080",
		"http://127.0.0.1.nip.io:8080",
	} {
		c, err := client.New(client.WithBaseURL(raw), client.WithInsecureTransport())
		require.Error(t, err, "non-loopback host %s must be rejected", raw)
		require.Nil(t, c)
	}
}

// TestPartyAuthWithoutSignerFailsBeforeNetworkIO asserts the signer gate: a
// party-auth request on a client without WithSigner returns ErrNoSigner and
// the server records zero requests.
func TestPartyAuthWithoutSignerFailsBeforeNetworkIO(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c, err := client.New(client.WithBaseURL(srv.URL), client.WithInsecureTransport())
	require.NoError(t, err)

	resp, err := c.Do(context.Background(), client.Request{
		Method: http.MethodGet,
		Path:   "/v1/health",
		Auth:   wire.AuthParty,
	})
	require.ErrorIs(t, err, client.ErrNoSigner)
	assert.Nil(t, resp)
	assert.Zero(t, hits.Load(), "the signer gate must deny before any network I/O")
}

// TestResponseBodyCloseErrcheckClean asserts the deferred response-body close
// is errcheck-clean: the close error is explicitly discarded instead of being
// dropped bare (the .golangci.yml errcheck gate on client/client.go).
func TestResponseBodyCloseErrcheckClean(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err, "the package directory must be readable")

	const (
		bareClose    = "defer resp.Body.Close()"
		ignoredClose = "defer func() { _ = resp.Body.Close() }()"
	)
	foundIgnored := false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, readErr := os.ReadFile(name)
		require.NoError(t, readErr)
		require.NotContains(t, string(src), bareClose,
			"%s: a bare deferred close fails errcheck; discard the error explicitly", name)
		if strings.Contains(string(src), ignoredClose) {
			foundIgnored = true
		}
	}
	require.True(t, foundIgnored,
		"a deferred body close with an explicit ignored error must exist in the package")
}
