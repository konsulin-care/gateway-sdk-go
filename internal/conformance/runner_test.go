package conformance

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// passCase builds a synthetic passing registry case under name.
func passCase(name string) Case {
	return Case{
		Name: name,
		Kind: KindPositive,
		Run:  func(context.Context, *Env) error { return nil },
	}
}

// failCase builds a synthetic failing registry case under name that
// reports err.
func failCase(name string, err error) Case {
	return Case{
		Name: name,
		Kind: KindPositive,
		Run:  func(context.Context, *Env) error { return err },
	}
}

// TestConformanceGreenRunExitsZero asserts a run where every case
// passes returns exit code 0 and stdout names each executed case
// (SDK-CONF-C01).
func TestConformanceGreenRunExitsZero(t *testing.T) {
	cases := []Case{passCase("alpha"), passCase("beta"), passCase("gamma")}

	var stdout, stderr bytes.Buffer
	code := runCases(context.Background(), cases, &Env{}, 0, &stdout, &stderr)

	require.Equal(t, ExitOK, code, "a green run must return exit code 0")
	for _, name := range []string{"alpha", "beta", "gamma"} {
		assert.Contains(t, stdout.String(), "PASS "+name,
			"stdout must name each executed case")
	}
	assert.Empty(t, stderr.String(), "a green run prints nothing to stderr")
}

// TestConformanceMismatchExitsNonZeroNamingCase asserts a run with one
// mismatched case returns a non-zero exit code and stderr contains that
// case name (SDK-CONF-C01).
func TestConformanceMismatchExitsNonZeroNamingCase(t *testing.T) {
	cases := []Case{
		passCase("alpha"),
		failCase("beta", errors.New("contract mismatch")),
		passCase("gamma"),
	}

	var stdout, stderr bytes.Buffer
	code := runCases(context.Background(), cases, &Env{}, 0, &stdout, &stderr)

	require.Equal(t, ExitMismatch, code, "one mismatched case must return a non-zero exit code")
	assert.Contains(t, stdout.String(), "FAIL beta", "stdout reports the failing case with its error")
	assert.Contains(t, stderr.String(), "beta", "stderr must contain the failing case name")
	assert.NotContains(t, stderr.String(), "alpha", "passing cases are not failing cases")
	assert.NotContains(t, stderr.String(), "gamma", "passing cases are not failing cases")
}

// TestConformanceMissingConfigExitsUsageErrorBeforeAnyRequest asserts a
// missing required configuration value (base URL or operator
// credentials) exits non-zero with a usage error before any request is
// issued, and that the usage error never carries a config value.
func TestConformanceMissingConfigExitsUsageErrorBeforeAnyRequest(t *testing.T) {
	var hits atomic.Int32
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(gateway.Close)

	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{"no config", &Config{}, "base URL"},
		{"missing operator user", &Config{BaseURL: gateway.URL}, "operator user"},
		{"missing operator password", &Config{BaseURL: gateway.URL, OperatorUser: "operator"}, "operator password"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), tc.cfg, &stdout, &stderr)
			require.Equal(t, ExitUsage, code, "a missing required value must exit non-zero")
			assert.Contains(t, stderr.String(), tc.wantErr, "the usage error must name the missing value")
			assert.Empty(t, stdout.String(), "no case runs on a usage error")
		})
	}
	assert.Zero(t, hits.Load(), "no request may be issued before the configuration is complete")
}

// TestConformanceRunNeverPrintsOperatorPassword asserts a full run's
// stdout and stderr never contain the operator password — the report
// carries case names and results only (PRD §8).
func TestConformanceRunNeverPrintsOperatorPassword(t *testing.T) {
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(gateway.Close)

	const opPassValue = "op-pass-sentinel-3f9c"
	cfg := &Config{
		BaseURL:      gateway.URL,
		OperatorUser: "operator",
		OperatorPass: opPassValue,
		Timeout:      200 * time.Millisecond,
	}

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), cfg, &stdout, &stderr)

	require.Equal(t, ExitMismatch, code, "a 404 target must fail every case")
	combined := stdout.String() + stderr.String()
	assert.NotContains(t, combined, opPassValue, "the operator password must never be printed")
	assert.Contains(t, stdout.String(), "FAIL health", "the run still reports each executed case")
}

// TestVersionIsReadFromBuildInfo asserts Version reports a non-empty
// runner version derived from the Go build info (SDK-CONF-003) and
// never leaks the raw "(devel)" marker.
func TestVersionIsReadFromBuildInfo(t *testing.T) {
	version := Version()
	assert.NotEmpty(t, version, "the runner version must never be empty")
	assert.NotEqual(t, "(devel)", version, "the raw build-info marker must be normalized")
}

// TestNewCallbackReceiverBindsExplicitAddr asserts the runner binds the
// result-callback receiver on the configured address when one is set.
func TestNewCallbackReceiverBindsExplicitAddr(t *testing.T) {
	r, err := newCallbackReceiver("127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(r.Close)
	assert.Contains(t, r.URL(), "127.0.0.1:", "the receiver must bind the configured address")
}

// captureCase builds a synthetic registry case that records the Env
// it runs against into captured.
func captureCase(captured chan<- *Env) Case {
	return Case{
		Name: "capture",
		Kind: KindPositive,
		Run: func(_ context.Context, env *Env) error {
			captured <- env
			return nil
		},
	}
}

// conformance404Gateway starts a target gateway stub that answers 404
// to every request so a run never contacts a real gateway.
func conformance404Gateway(t *testing.T) string {
	t.Helper()
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(gateway.Close)
	return gateway.URL
}

// TestRunThreadsCallbackURLAndPartyHealthURLIntoEnv asserts Run
// threads the configured callback URL and party health URL from the
// Config into the case Env, so the bootstrap case registers them as
// endpoints.callbacks and endpoints.health.
func TestRunThreadsCallbackURLAndPartyHealthURLIntoEnv(t *testing.T) {
	cfg := &Config{
		BaseURL:        conformance404Gateway(t),
		OperatorUser:   "operator",
		OperatorPass:   "op-pass-sentinel-t5",
		CallbackURL:    "https://runner.example.test/callbacks/result",
		PartyHealthURL: "http://party.example.test:9090/health",
	}
	captured := make(chan *Env, 1)

	var stdout, stderr bytes.Buffer
	code := runRegistry(context.Background(), cfg, []Case{captureCase(captured)}, &stdout, &stderr)

	require.Equal(t, ExitOK, code, "the capture case must pass")
	env := <-captured
	require.NotNil(t, env, "the case must observe the run Env")
	assert.Equal(t, "https://runner.example.test/callbacks/result", env.CallbackURL,
		"Run must thread the configured callback URL into the case Env")
	assert.Equal(t, "https://runner.example.test/callbacks/result", env.callbackURL(),
		"the env callback URL must prefer the configured value")
	assert.Equal(t, "http://party.example.test:9090/health", env.PartyHealthURL,
		"Run must thread the configured party health URL into the case Env")
	assert.Equal(t, "http://party.example.test:9090/health", env.partyHealthURL(),
		"the env party health URL must prefer the configured value")
}

// TestRunCallbackURLFallsBackToReceiverLoopbackURL asserts that when
// no callback URL is configured, the Env callback URL falls back to
// the result-callback receiver's loopback URL.
func TestRunCallbackURLFallsBackToReceiverLoopbackURL(t *testing.T) {
	cfg := &Config{
		BaseURL:      conformance404Gateway(t),
		OperatorUser: "operator",
		OperatorPass: "op-pass-sentinel-t5",
	}
	captured := make(chan *Env, 1)

	var stdout, stderr bytes.Buffer
	code := runRegistry(context.Background(), cfg, []Case{captureCase(captured)}, &stdout, &stderr)

	require.Equal(t, ExitOK, code, "the capture case must pass")
	env := <-captured
	require.NotNil(t, env, "the case must observe the run Env")
	assert.Empty(t, env.CallbackURL, "no callback URL is configured")
	require.NotNil(t, env.Callback, "the run must start the callback receiver")
	assert.Equal(t, env.Callback.URL(), env.callbackURL(),
		"with no callback URL configured, the Env callback URL must fall back to the receiver's URL")
	assert.Contains(t, env.callbackURL(), "127.0.0.1:",
		"the fallback must be the receiver's loopback URL")
}
