package client_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// retryStep is one scripted gateway answer: status/header/body, or err to
// fail the attempt at the transport layer.
type retryStep struct {
	status int
	header http.Header
	body   string
	err    error
}

// errEnvelope builds a gateway error-envelope body carrying code.
func errEnvelope(code string) string {
	return `{"error":{"code":"` + code + `","message":"m","request_id":"r1"}}`
}

// retryScript answers scripted steps in order (the last repeats) and
// records one entry per attempt under a mutex: Idempotency-Key, body
// bytes, and the jti parsed from the Authorization token. Race-safe.
type retryScript struct {
	mu     sync.Mutex
	steps  []retryStep
	keys   []string
	bodies [][]byte
	jtis   []string
}

// roundTrip records this attempt's key, body bytes and jti, then answers
// the next scripted step (the last step repeats).
func (s *retryScript) roundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.keys = append(s.keys, r.Header.Get("Idempotency-Key"))
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	s.bodies = append(s.bodies, body)
	s.jtis = append(s.jtis, bearerJti(r.Header.Get("Authorization")))
	step := s.steps[min(len(s.keys)-1, len(s.steps)-1)]
	s.mu.Unlock()
	if step.err != nil {
		return nil, step.err
	}
	return stubResponse(r, step.status, step.header, step.body), nil
}

// attempts returns the number of attempts recorded so far.
func (s *retryScript) attempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}

// bearerJti extracts the jti claim from a "Bearer a.b.c" Authorization
// value; "" when absent or unparseable.
func bearerJti(authorization string) string {
	segments := strings.Split(strings.TrimPrefix(authorization, "Bearer "), ".")
	if len(segments) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Jti string `json:"jti"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Jti
}

// retryEnv holds the injected retry doubles of one test client: the
// sleeper records delays without waiting, the clock reads now, and jitter
// draws come from jitter.
type retryEnv struct {
	mu     sync.Mutex
	now    time.Time
	jitter func(int64) int64
	delays []time.Duration
}

// sleep records the requested delay instead of waiting (sleeper hook).
func (e *retryEnv) sleep(_ context.Context, d time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.delays = append(e.delays, d)
	return nil
}

// recorded returns the backoff delays recorded so far.
func (e *retryEnv) recorded() []time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]time.Duration(nil), e.delays...)
}

// jitterAt pins every jitter draw to its minimum (0) or maximum (n-1) end
// so backoff bounds assert deterministically.
func jitterAt(max bool) func(int64) int64 {
	if max {
		return func(n int64) int64 { return n - 1 }
	}
	return func(int64) int64 { return 0 }
}

// newRetryTestClient builds an auth-party Client over script with policy
// p and deterministic retry hooks derived from env.
func newRetryTestClient(t *testing.T, script *retryScript, p client.RetryPolicy, env *retryEnv) *client.Client {
	t.Helper()
	_, priv := newPartyKey(t)
	c, err := client.New(
		client.WithBaseURL("https://gw.example"),
		client.WithSigner("party-1", priv),
		client.WithHTTPClient(&http.Client{Transport: client.RoundTripFunc(script.roundTrip)}),
		client.WithLogger(client.NewLogCapture().Logger()),
		client.WithRetry(p),
	)
	require.NoError(t, err)
	client.SetSleepHook(c, env.sleep)
	client.SetNowHook(c, func() time.Time { return env.now })
	client.SetJitterHook(c, env.jitter)
	return c
}

// TestRetry409To200ReplaysSameKeyNewJti covers SDK-RETRY-C01: a 409
// GW-API-002 then 200 replays as two attempts under one Idempotency-Key
// with two distinct jtis (SDK-RETRY-001).
func TestRetry409To200ReplaysSameKeyNewJti(t *testing.T) {
	script := &retryScript{steps: []retryStep{
		{status: http.StatusConflict, body: errEnvelope("GW-API-002")},
		{status: http.StatusOK, body: `{"ok":true}`},
	}}
	env := &retryEnv{now: time.Unix(1700000000, 0), jitter: jitterAt(true)}
	c := newRetryTestClient(t, script, client.RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Second}, env)

	resp, err := c.Do(context.Background(), client.Request{
		Method: http.MethodPost, Path: "/v1/listings",
		Body: []byte(`{"amount":10}`), Auth: wire.AuthParty, Idempotent: true,
	})
	require.NoError(t, err, "the 409 GW-API-002 then 200 sequence must succeed")
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	require.Len(t, script.keys, 2, "the 409 must cost exactly one replay")
	require.NotEmpty(t, script.keys[0])
	assert.Equal(t, script.keys[0], script.keys[1], "both attempts share one Idempotency-Key")
	require.NotEmpty(t, script.jtis[0])
	require.NotEmpty(t, script.jtis[1])
	assert.NotEqual(t, script.jtis[0], script.jtis[1],
		"the replay must sign a fresh jti, never the first attempt's")
}

// TestRetry403TerminalOnFirstAttempt: a 403 capability_denied returns its
// *wire.Error after exactly one attempt, even under a 3-attempt policy
// (SDK-RETRY-003) — never wrapped in ErrOutcomeUnknown.
func TestRetry403TerminalOnFirstAttempt(t *testing.T) {
	script := &retryScript{steps: []retryStep{
		{status: http.StatusForbidden, body: errEnvelope("capability_denied")},
	}}
	env := &retryEnv{now: time.Unix(1700000000, 0), jitter: jitterAt(true)}
	c := newRetryTestClient(t, script, client.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Second}, env)

	_, err := c.Do(context.Background(), client.Request{
		Method: http.MethodGet, Path: "/v1/things", Auth: wire.AuthParty,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, wire.ErrCapabilityDenied)
	assert.NotErrorIs(t, err, client.ErrOutcomeUnknown, "a terminal response is a known outcome")
	assert.Empty(t, env.recorded(), "a terminal response must never back off")
	assert.Equal(t, 1, script.attempts(), "a 403 must cost exactly one attempt")
}

// TestEveryAttemptFreshJtiSameBodyBytes: each attempt of one logical call
// carries a fresh jti and byte-identical base body (SDK-RETRY-001).
func TestEveryAttemptFreshJtiSameBodyBytes(t *testing.T) {
	script := &retryScript{steps: []retryStep{
		{status: http.StatusServiceUnavailable},
		{status: http.StatusServiceUnavailable},
		{status: http.StatusOK, body: `{"ok":true}`},
	}}
	env := &retryEnv{now: time.Unix(1700000000, 0), jitter: jitterAt(true)}
	c := newRetryTestClient(t, script, client.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Second}, env)

	_, err := c.Do(context.Background(), client.Request{
		Method: http.MethodPost, Path: "/v1/listings",
		Body: []byte(`{"amount":10}`), Auth: wire.AuthParty,
	})
	require.NoError(t, err)

	require.Len(t, script.jtis, 3)
	seen := map[string]bool{}
	for i, jti := range script.jtis {
		require.NotEmpty(t, jti, "attempt %d must sign a jti", i+1)
		assert.False(t, seen[jti], "attempt %d replayed jti %q", i+1, jti)
		seen[jti] = true
		assert.Equal(t, script.bodies[0], script.bodies[i],
			"attempt %d must resend the identical base body bytes", i+1)
	}
}

// TestRetryClassificationMatrixCoversStatusAndCodes drives the SDK-RETRY
// disposition matrix through the client: 429/502/503/504 and 409
// GW-API-002 are retried within a 2-attempt budget; 400, 401, 402, 403,
// 409 GW-PARTY-006, 413 and 422 return after one attempt; an unrecognised
// GW-* code classifies from the HTTP status (SDK-RETRY-002/003, ADR-012).
func TestRetryClassificationMatrixCoversStatusAndCodes(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		code         string
		wantAttempts int
	}{
		{"429 retried", http.StatusTooManyRequests, "GW-RATE-001", 2},
		{"502 retried", http.StatusBadGateway, "", 2},
		{"503 retried", http.StatusServiceUnavailable, "", 2},
		{"504 retried", http.StatusGatewayTimeout, "", 2},
		{"409 GW-API-002 retried", http.StatusConflict, "GW-API-002", 2},
		{"unknown code on 503 retried", http.StatusServiceUnavailable, "GW-FUTURE-999", 2},
		{"400 terminal", http.StatusBadRequest, "", 1},
		{"401 terminal", http.StatusUnauthorized, "GW-PARTY-007", 1},
		{"402 terminal", http.StatusPaymentRequired, "GW-HOOK-006", 1},
		{"403 terminal", http.StatusForbidden, "capability_denied", 1},
		{"409 GW-PARTY-006 terminal", http.StatusConflict, "GW-PARTY-006", 1},
		{"413 terminal", http.StatusRequestEntityTooLarge, "", 1},
		{"422 terminal", http.StatusUnprocessableEntity, "GW-HOOK-008", 1},
		{"unknown code on 400 terminal", http.StatusBadRequest, "GW-FUTURE-999", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := ""
			if tc.code != "" {
				body = errEnvelope(tc.code)
			} else {
				body = "upstream unavailable"
			}
			script := &retryScript{steps: []retryStep{
				{status: tc.status, body: body},
				{status: http.StatusOK, body: `{"ok":true}`},
			}}
			env := &retryEnv{now: time.Unix(1700000000, 0), jitter: jitterAt(true)}
			c := newRetryTestClient(t, script, client.RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}, env)

			_, err := c.Do(context.Background(), client.Request{
				Method: http.MethodPost, Path: "/v1/listings",
				Body: []byte(`{"amount":10}`), Auth: wire.AuthParty,
			})
			assert.Equal(t, tc.wantAttempts, script.attempts(), "attempt count")
			if tc.wantAttempts == 2 {
				require.NoError(t, err, "a retryable row must succeed on the replay")
				return
			}
			require.Error(t, err)
			var gwErr *wire.Error
			require.ErrorAs(t, err, &gwErr, "a terminal row surfaces its *wire.Error")
			if tc.code != "" {
				assert.Equal(t, tc.code, gwErr.Code)
			}
		})
	}
}

// TestRetryAfterHonouredSecondsDateAndCap: a Retry-After header overrides
// the exponential schedule — the delta-seconds form sleeps exactly N
// seconds, the HTTP-date form sleeps the distance from the injected
// clock, and either is capped at MaxDelay (SDK-RETRY-002).
func TestRetryAfterHonouredSecondsDateAndCap(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cases := []struct {
		name      string
		header    func() string
		maxDelay  time.Duration
		wantDelay time.Duration
	}{
		{"seconds", func() string { return "7" }, 30 * time.Second, 7 * time.Second},
		{"http-date", func() string { return now.Add(13 * time.Second).Format(http.TimeFormat) }, 30 * time.Second, 13 * time.Second},
		{"capped at MaxDelay", func() string { return "120" }, 10 * time.Second, 10 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := &retryScript{steps: []retryStep{
				{status: http.StatusServiceUnavailable, header: http.Header{"Retry-After": []string{tc.header()}}},
				{status: http.StatusOK, body: `{"ok":true}`},
			}}
			env := &retryEnv{now: now, jitter: jitterAt(true)}
			c := newRetryTestClient(t, script, client.RetryPolicy{MaxAttempts: 2, BaseDelay: 100 * time.Millisecond, MaxDelay: tc.maxDelay}, env)

			_, err := c.Do(context.Background(), client.Request{
				Method: http.MethodGet, Path: "/v1/health", Auth: wire.AuthParty,
			})
			require.NoError(t, err)
			assert.Equal(t, []time.Duration{tc.wantDelay}, env.recorded(),
				"the sleeper must receive exactly the Retry-After delay")
		})
	}
}

// TestBackoffGrowsExponentialJitterCappedMaxDelay: the computed delay for
// attempt i is BaseDelay*2^(i-1) shrunk by jitter into [base/2, base] and
// never exceeding MaxDelay, at both jitter extremes (SDK-RETRY-002).
func TestBackoffGrowsExponentialJitterCappedMaxDelay(t *testing.T) {
	policy := client.RetryPolicy{MaxAttempts: 5, BaseDelay: 100 * time.Millisecond, MaxDelay: 250 * time.Millisecond}
	steps := []retryStep{{status: http.StatusServiceUnavailable}}
	for i := 0; i < 4; i++ {
		steps = append(steps, retryStep{status: http.StatusServiceUnavailable})
	}
	wantMax := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 250 * time.Millisecond, 250 * time.Millisecond}
	wantMin := []time.Duration{50 * time.Millisecond, 100 * time.Millisecond, 125 * time.Millisecond, 125 * time.Millisecond}

	for _, tc := range []struct {
		name string
		max  bool
		want []time.Duration
	}{{"jitter max", true, wantMax}, {"jitter min", false, wantMin}} {
		t.Run(tc.name, func(t *testing.T) {
			script := &retryScript{steps: steps}
			env := &retryEnv{now: time.Unix(1700000000, 0), jitter: jitterAt(tc.max)}
			c := newRetryTestClient(t, script, policy, env)

			_, err := c.Do(context.Background(), client.Request{
				Method: http.MethodGet, Path: "/v1/health", Auth: wire.AuthParty,
			})
			require.ErrorIs(t, err, client.ErrOutcomeUnknown, "the budget must be exhausted, never looping")
			assert.Equal(t, 5, script.attempts())
			assert.Equal(t, tc.want, env.recorded(), "delays must grow exponentially and cap at MaxDelay")
			for _, d := range env.recorded() {
				assert.LessOrEqual(t, d, policy.MaxDelay, "no delay may exceed MaxDelay")
			}
		})
	}
}

// TestNetworkErrorsExhaustToErrOutcomeUnknown: repeated transport errors
// stop after MaxAttempts and surface an error wrapping ErrOutcomeUnknown
// plus the last transport error (SDK-RETRY-002 boundedness).
func TestNetworkErrorsExhaustToErrOutcomeUnknown(t *testing.T) {
	netErr := errors.New("dial tcp: connection refused")
	script := &retryScript{steps: []retryStep{{err: netErr}}}
	env := &retryEnv{now: time.Unix(1700000000, 0), jitter: jitterAt(true)}
	c := newRetryTestClient(t, script, client.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Second}, env)

	_, err := c.Do(context.Background(), client.Request{
		Method: http.MethodGet, Path: "/v1/health", Auth: wire.AuthParty,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, client.ErrOutcomeUnknown, "network exhaustion is an unknown outcome")
	assert.ErrorIs(t, err, netErr, "the last transport error stays in the chain")
	assert.Equal(t, 3, script.attempts(), "network errors must stop after MaxAttempts")
	require.Len(t, env.recorded(), 2, "two backoffs separate three attempts")
}

// TestStatusExhaustionWrapsOutcomeUnknownAndWireError: exhausting the
// budget on retryable statuses returns an error matching both
// ErrOutcomeUnknown and the last *wire.Error (SDK-RETRY-002).
func TestStatusExhaustionWrapsOutcomeUnknownAndWireError(t *testing.T) {
	script := &retryScript{steps: []retryStep{
		{status: http.StatusServiceUnavailable, body: errEnvelope("GW-HOOK-009")},
	}}
	env := &retryEnv{now: time.Unix(1700000000, 0), jitter: jitterAt(true)}
	c := newRetryTestClient(t, script, client.RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Second}, env)

	_, err := c.Do(context.Background(), client.Request{
		Method: http.MethodGet, Path: "/v1/health", Auth: wire.AuthParty,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, client.ErrOutcomeUnknown)
	var gwErr *wire.Error
	require.ErrorAs(t, err, &gwErr, "the last gateway error stays in the chain")
	assert.Equal(t, "GW-HOOK-009", gwErr.Code)
	assert.Equal(t, http.StatusServiceUnavailable, gwErr.Status)
	assert.Equal(t, 2, script.attempts())
}

// TestCancellationDuringBackoffStopsPromptly: a context cancelled while
// waiting out a backoff returns context.Error promptly with no further
// attempt — via the injected sleeper and via the production timer
// (PRD §10: retry backoff never blocks cancellation).
func TestCancellationDuringBackoffStopsPromptly(t *testing.T) {
	t.Run("injected sleeper", func(t *testing.T) {
		script := &retryScript{steps: []retryStep{{status: http.StatusServiceUnavailable}}}
		env := &retryEnv{now: time.Unix(1700000000, 0), jitter: jitterAt(true)}
		c := newRetryTestClient(t, script, client.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Second, MaxDelay: time.Second}, env)
		ctx, cancel := context.WithCancel(context.Background())
		client.SetSleepHook(c, func(context.Context, time.Duration) error {
			cancel()
			return ctx.Err()
		})

		_, err := c.Do(ctx, client.Request{Method: http.MethodGet, Path: "/v1/health", Auth: wire.AuthParty})
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, 1, script.attempts(), "cancellation during backoff must stop the loop")
	})

	t.Run("production sleeper", func(t *testing.T) {
		var hits int
		var mu sync.Mutex
		transport := client.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			mu.Lock()
			hits++
			first := hits == 1
			mu.Unlock()
			if first {
				return nil, r.Context().Err()
			}
			return stubResponse(r, http.StatusServiceUnavailable, nil, ""), nil
		})
		c, err := client.New(
			client.WithBaseURL("https://gw.example"),
			client.WithHTTPClient(&http.Client{Transport: transport}),
			client.WithLogger(client.NewLogCapture().Logger()),
			client.WithRetry(client.RetryPolicy{MaxAttempts: 2, BaseDelay: 5 * time.Second, MaxDelay: 5 * time.Second}),
		)
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())

		// first attempt fails as the transport cancels the call mid-flight;
		// the following 5s backoff must abort on the cancelled context.
		done := make(chan error, 1)
		go func() {
			_, doErr := c.Do(ctx, client.Request{Method: http.MethodGet, Path: "/v1/health", Auth: wire.AuthPublic})
			done <- doErr
		}()
		go func() {
			for {
				mu.Lock()
				n := hits
				mu.Unlock()
				if n >= 1 {
					cancel()
					return
				}
				time.Sleep(time.Millisecond)
			}
		}()
		select {
		case doErr := <-done:
			require.ErrorIs(t, doErr, context.Canceled)
			mu.Lock()
			defer mu.Unlock()
			assert.Equal(t, 1, hits, "no attempt may start after cancellation")
		case <-time.After(2 * time.Second):
			t.Fatal("Do did not return promptly after cancellation during backoff")
		}
	})
}

// recordReplayCache records every reservation and answers with its
// scripted fresh/error verdicts; race-safe.
type recordReplayCache struct {
	mu     sync.Mutex
	scopes []string
	keys   []string
	fresh  bool
	err    error
}

// Check records the reservation attempt and answers the scripted verdict.
func (c *recordReplayCache) Check(_ context.Context, scope, key string, _ time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scopes = append(c.scopes, scope)
	c.keys = append(c.keys, key)
	return c.fresh, c.err
}

// Release is a no-op.
func (c *recordReplayCache) Release(context.Context, string, string) error { return nil }

// TestReplayCacheReservesJTIPerAttempt: with WithReplayCache every
// attempt's fresh jti is reserved in scope "jti" before sending
// (SDK-RETRY-001 with replay reservation).
func TestReplayCacheReservesJTIPerAttempt(t *testing.T) {
	script := &retryScript{steps: []retryStep{
		{status: http.StatusServiceUnavailable},
		{status: http.StatusOK, body: `{"ok":true}`},
	}}
	env := &retryEnv{now: time.Unix(1700000000, 0), jitter: jitterAt(true)}
	c := newRetryTestClient(t, script, client.RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Second}, env)
	cache := &recordReplayCache{fresh: true}
	client.SetReplayCache(c, cache)

	_, err := c.Do(context.Background(), client.Request{
		Method: http.MethodGet, Path: "/v1/health", Auth: wire.AuthParty,
	})
	require.NoError(t, err)

	cache.mu.Lock()
	defer cache.mu.Unlock()
	require.Equal(t, []string{"jti", "jti"}, cache.scopes, "each attempt reserves scope jti")
	require.Len(t, cache.keys, 2)
	for i, key := range cache.keys {
		require.NotEmpty(t, key)
		assert.Equal(t, script.jtis[i], key, "the reserved jti must be the one this attempt signed")
	}
	assert.NotEqual(t, cache.keys[0], cache.keys[1], "each attempt reserves a fresh jti")
}

// TestReplayCacheFailureOrDuplicateFailsBeforeSend: a reservation error
// or a duplicate verdict fails the attempt before any network I/O
// (fail closed), and is not an ErrOutcomeUnknown retry exhaustion.
func TestReplayCacheFailureOrDuplicateFailsBeforeSend(t *testing.T) {
	cases := []struct {
		name  string
		fresh bool
		err   error
	}{
		{"reservation error", true, errors.New("cache unavailable")},
		{"duplicate jti", false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := &retryScript{steps: []retryStep{{status: http.StatusOK, body: `{}`}}}
			env := &retryEnv{now: time.Unix(1700000000, 0), jitter: jitterAt(true)}
			c := newRetryTestClient(t, script, client.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Second}, env)
			client.SetReplayCache(c, &recordReplayCache{fresh: tc.fresh, err: tc.err})

			_, err := c.Do(context.Background(), client.Request{
				Method: http.MethodGet, Path: "/v1/health", Auth: wire.AuthParty,
			})
			require.Error(t, err, "a failed or duplicate reservation must fail the attempt")
			assert.NotErrorIs(t, err, client.ErrOutcomeUnknown,
				"a reservation failure is a known client-side failure, not an unknown outcome")
			assert.Zero(t, script.attempts(), "no request may be sent without a reserved jti")
		})
	}
}

// TestParallelDoOnOneClientIsRaceClean: concurrent Do calls on one Client
// (SDK-CLIENT-001 thread safety) pass under -race with retries enabled.
func TestParallelDoOnOneClientIsRaceClean(t *testing.T) {
	script := &retryScript{steps: []retryStep{{status: http.StatusOK, body: `{"ok":true}`}}}
	env := &retryEnv{now: time.Unix(1700000000, 0), jitter: jitterAt(true)}
	c := newRetryTestClient(t, script, client.RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond}, env)

	const workers = 16
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := c.Do(context.Background(), client.Request{
				Method: http.MethodPost, Path: "/v1/listings",
				Body: []byte(`{"amount":10}`), Auth: wire.AuthParty, Idempotent: true,
			})
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "worker %d", i)
	}
	assert.Equal(t, workers, script.attempts(), "one attempt per parallel call")
}
