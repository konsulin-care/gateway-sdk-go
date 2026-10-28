package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/gatewaytest"
	"github.com/konsulin-care/gateway-sdk-go/verify"
)

// recipientPartyID is the recipient party every inbound gateway token in
// these flows is addressed to (aud) and the verifier's self identity.
const recipientPartyID = "01HZYRECIPIENT000001"

// offlineDialer is the only dialer the guarded transport reaches; it runs
// only after the loopback check has passed.
var offlineDialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}

// TestMain installs the zero-network guard before any test runs: every
// request through http.DefaultTransport — the default for
// http.DefaultClient, for the SDK client without WithHTTPClient, and for
// the verifier's JWKS fetch — is dialed through a context that refuses
// any non-loopback address, so a stray outbound call fails locally
// instead of touching the network (SDK-TEST-002, zero network by
// construction).
func TestMain(m *testing.M) {
	http.DefaultTransport = loopbackOnlyTransport()
	os.Exit(m.Run())
}

// loopbackOnlyTransport clones the default transport with proxying off
// and a dial function that refuses every non-loopback address, so the
// probe in TestMainInstallsLoopbackOnlyDial is deterministic and never
// resolves or dials a public host.
//
// Returns: the guarded transport installed as http.DefaultTransport.
func loopbackOnlyTransport() http.RoundTripper {
	tr, _ := http.DefaultTransport.(*http.Transport)
	if tr == nil {
		tr = &http.Transport{}
	} else {
		tr = tr.Clone()
	}
	tr.Proxy = nil
	tr.DialContext = guardedDial
	return tr
}

// guardedDial dials addr only when its host is loopback (localhost or a
// loopback IP); any other address fails with an error naming the refusal
// before any socket or DNS lookup happens.
//
// Parameters: ctx carries cancellation; network is the dial network;
// addr is "host:port".
// Returns: the loopback connection, or the refusal/parse error.
func guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("integration: dial %q: %w", addr, err)
	}
	if !isLoopbackHost(host) {
		return nil, fmt.Errorf("integration: non-loopback dial refused: %q", addr)
	}
	return offlineDialer.DialContext(ctx, network, addr)
}

// isLoopbackHost reports "localhost" (any case) or a loopback IP literal.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// TestMainInstallsLoopbackOnlyDial proves the TestMain guard: a direct
// dial to a non-loopback address fails with the refusal, and a probe
// request to a public address through the installed transport fails the
// same way — zero network by construction (SDK-TEST-002).
func TestMainInstallsLoopbackOnlyDial(t *testing.T) {
	tr, ok := http.DefaultTransport.(*http.Transport)
	require.True(t, ok, "TestMain must install a guarded *http.Transport")

	_, err := tr.DialContext(context.Background(), "tcp", "203.0.113.1:443")
	require.Error(t, err, "a dial to a non-loopback address must fail")
	assert.Contains(t, err.Error(), "non-loopback dial refused")

	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.Error(t, err, "a probe dial to a public address must fail")
	assert.Nil(t, resp, "a refused probe must produce no response")
	assert.Contains(t, err.Error(), "non-loopback dial refused")
}

// fixture is the shared offline environment every flow runs against: one
// fake gateway, one gateway signing minter with its JWKS endpoint, one
// deterministic replay cache, a verifier over that cache, and one
// party-authenticated SDK client with bounded retry.
type fixture struct {
	g        *gatewaytest.Gateway
	minter   *gatewaytest.Minter
	jwks     *gatewaytest.JWKSServer
	replay   *gatewaytest.ReplayCache
	verifier *verify.Verifier
	cli      *client.Client
}

// newFixture builds the shared fixture and registers its cleanup.
//
// Parameters: t is the test (registers cleanup).
// Returns: the ready-to-use fixture.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	g := gatewaytest.NewGateway()
	t.Cleanup(g.Close)

	minter, err := gatewaytest.NewMinter()
	require.NoError(t, err)
	doc, err := minter.JWKS()
	require.NoError(t, err)
	jwks, err := gatewaytest.NewJWKSServer(doc)
	require.NoError(t, err)
	t.Cleanup(jwks.Close)

	replay := gatewaytest.NewReplayCache()
	verifier, err := verify.NewVerifier(jwks.URL(), recipientPartyID,
		verify.WithReplayCache(replay))
	require.NoError(t, err)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cli, err := client.New(
		client.WithBaseURL(g.URL()),
		client.WithInsecureTransport(),
		client.WithSigner(testPartyID, priv),
		client.WithReplayCache(replay),
		client.WithRetry(client.RetryPolicy{
			MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond,
		}),
	)
	require.NoError(t, err)

	return &fixture{g: g, minter: minter, jwks: jwks, replay: replay,
		verifier: verifier, cli: cli}
}

// TestIntegrationFlowsOffline runs the SDK-TEST-002 offline flows as
// subtests against the shared fixture: enroll, signed-calls, exchange and
// callback — zero network, every request loopback-only by TestMain.
func TestIntegrationFlowsOffline(t *testing.T) {
	fx := newFixture(t)
	t.Run("enroll", func(t *testing.T) { runEnrollFlow(t, fx) })
	t.Run("signed-calls", func(t *testing.T) { runSignedCallsFlow(t, fx) })
	t.Run("exchange", func(t *testing.T) { runExchangeFlow(t, fx) })
	t.Run("callback", func(t *testing.T) { runCallbackFlow(t, fx) })
}

// rfc7638Thumbprint computes the RFC 7638 thumbprint of an OKP public
// key: SHA-256 over the canonical JSON of the required members in
// lexicographic order (crv, kty, x), base64url (unpadded).
//
// Parameters: t is the test; kty is "OKP"; crv is the curve; x is the
// base64url public coordinate.
// Returns: the thumbprint.
func rfc7638Thumbprint(t *testing.T, kty, crv, x string) string {
	t.Helper()
	canonical, err := json.Marshal(map[string]string{"crv": crv, "kty": kty, "x": x})
	require.NoError(t, err)
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// mustJSON marshals v or fails the test.
//
// Parameters: t is the test; v is the value to marshal.
// Returns: the JSON bytes.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
