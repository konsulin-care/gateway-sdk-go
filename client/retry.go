package client

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// ErrOutcomeUnknown reports that a call ended without a gateway decision
// (SDK-RETRY-002): the bounded retry budget ran out on transport errors or
// on retryable statuses, so the operation may or may not have been applied.
// errors.Is matches it; the last failure (transport error or *wire.Error)
// stays in the chain via errors.As/errors.Is. A terminal response is never
// wrapped in it — that is a known outcome.
var ErrOutcomeUnknown = errors.New("client: outcome unknown after bounded retries")

// errNetwork marks a transport-layer failure of one attempt so the retry
// loop (SDK-RETRY-002) can tell potentially transient network errors —
// retried within the budget — apart from local failures (signing, jti
// reservation, request build, body read), which are terminal.
var errNetwork = errors.New("client: network error")

// maxBackoffSpan is the hard ceiling on one computed exponential delay
// before the caller's MaxDelay applies; it bounds growth against overflow
// on very large attempt counts.
const maxBackoffSpan = time.Hour

// retryLoop runs the bounded retry of one logical call (SDK-RETRY-001,
// SDK-RETRY-002): up to attempts network attempts separated by a
// context-aware backoff honouring Retry-After, each attempt signing a
// fresh jti and reusing the call's single Idempotency-Key (ADR-008). A
// terminal or 2xx response, a local (non-network) failure, or a cancelled
// context ends the loop immediately; exhausting the budget on network
// errors or on retryable statuses returns an error wrapping
// ErrOutcomeUnknown with the last failure in the chain (fail closed:
// unknown is never a silent success).
// Parameters: ctx — the call context; req — the outbound request; key —
// the Idempotency-Key held stable across attempts; attempts — the total
// attempt budget (at least 1). Returns: the final response with its
// buffered body, or an error.
func (c *Client) retryLoop(ctx context.Context, req Request, key string, attempts int) (*Response, error) {
	for attempt := 1; ; attempt++ {
		out, err := c.attempt(ctx, req, key)
		if err != nil {
			if retry, stop := c.afterNetworkError(ctx, err, attempt, attempts); !retry {
				return nil, stop
			}
			continue
		}
		if !retryableResponse(out) {
			return out, nil
		}
		if attempt >= attempts {
			return nil, fmt.Errorf("client: retry budget exhausted after %d attempts: %w: %w",
				attempts, ErrOutcomeUnknown, wire.DecodeError(out.StatusCode, out.Body))
		}
		if err := c.backoff(ctx, attempt, out.Header); err != nil {
			return nil, err
		}
	}
}

// afterNetworkError prices one failed attempt (SDK-RETRY-002): a local
// failure (no errNetwork marker) is terminal and returned raw; a cancelled
// context stops the loop with the context error joined to the transport
// error; a network error within the budget backs off and retries; the last
// budgeted attempt wraps ErrOutcomeUnknown and the transport error together.
// Parameters: ctx — the call context; err — the attempt error; attempt —
// the 1-based attempt just finished; attempts — the total budget.
// Returns: whether to run one more attempt, and the error to return when
// not.
func (c *Client) afterNetworkError(ctx context.Context, err error, attempt, attempts int) (bool, error) {
	if !errors.Is(err, errNetwork) {
		return false, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, fmt.Errorf("client: aborted during retries: %w: %w", ctxErr, err)
	}
	if attempt >= attempts {
		return false, fmt.Errorf("client: retry budget exhausted after %d attempts: %w: %w",
			attempts, ErrOutcomeUnknown, err)
	}
	if err := c.backoff(ctx, attempt, nil); err != nil {
		return false, err
	}
	return true, nil
}

// backoff waits out the delay before the next attempt (SDK-RETRY-002): the
// delay is Retry-After-aware and capped at MaxDelay, a zero delay never
// sleeps, and a cancelled context aborts the wait with its error — backoff
// never blocks cancellation (PRD §10).
// Parameters: ctx — the call context; attempt — the attempt just finished;
// header — the response headers carrying Retry-After, nil when the attempt
// produced no response. Returns: nil when the wait completed, or the
// sleeper's or context's error.
func (c *Client) backoff(ctx context.Context, attempt int, header http.Header) error {
	d := c.delayFor(attempt, header)
	if d <= 0 {
		return nil
	}
	return c.sleep(ctx, d)
}

// delayFor computes the backoff delay after the given attempt
// (SDK-RETRY-002): the Retry-After header overrides the exponential
// schedule (server knowledge wins), and either way the result is capped at
// MaxDelay when set.
// Parameters: attempt — the attempt just finished; header — the response
// headers, nil when there was no response. Returns: the capped delay.
func (c *Client) delayFor(attempt int, header http.Header) time.Duration {
	if d, ok := retryAfter(header, c.now()); ok {
		return c.capDelay(d)
	}
	return c.jittered(attempt)
}

// retryAfter parses the Retry-After response header (SDK-RETRY-002): the
// delta-seconds form ("7") and the HTTP-date form (the distance from the
// injected clock, past dates clamped to zero). Parameters: header — the
// response headers (nil allowed); now — the injected clock reading.
// Returns: the delay, and whether a usable header was present.
func retryAfter(header http.Header, now time.Time) (time.Duration, bool) {
	raw := strings.TrimSpace(header.Get("Retry-After"))
	if raw == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		if secs < 0 {
			secs = 0
		}
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(raw); err == nil {
		// The injected clock's location frames the header's wall clock, so
		// a date minted from that same clock round-trips exactly even in a
		// non-UTC local zone (http.ParseTime reads the digits as UTC).
		u := when.UTC()
		local := time.Date(u.Year(), u.Month(), u.Day(), u.Hour(), u.Minute(), u.Second(), 0, now.Location())
		d := local.Sub(now)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

// jittered computes the exponential schedule for the given attempt
// (SDK-RETRY-002): BaseDelay doubled per attempt (bounded by
// maxBackoffSpan), capped at MaxDelay, then shrunk by jitter into
// [d/2, d] so parallel callers never synchronize — and a delay never
// exceeds the cap. Parameters: attempt — the attempt just finished.
// Returns: the jittered delay; zero for a zero BaseDelay.
func (c *Client) jittered(attempt int) time.Duration {
	d := c.retry.BaseDelay
	for i := 1; i < attempt; i++ {
		if d >= maxBackoffSpan/2 {
			d = maxBackoffSpan
			break
		}
		d *= 2
	}
	d = c.capDelay(d)
	if d <= 0 {
		return 0
	}
	half := d / 2
	return half + time.Duration(c.rand(int64(half)+1))
}

// capDelay caps d at the policy's MaxDelay; a zero MaxDelay means uncapped.
// Parameters: d — the delay to cap. Returns: the capped delay.
func (c *Client) capDelay(d time.Duration) time.Duration {
	if c.retry.MaxDelay > 0 && d > c.retry.MaxDelay {
		return c.retry.MaxDelay
	}
	return d
}

// defaultSleep waits out d or until ctx is done, whichever comes first
// (PRD §10: backoff never blocks cancellation). Parameters: ctx — the call
// context; d — the backoff delay. Returns: nil when the wait completed, or
// ctx.Err().
func defaultSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// defaultJitter draws uniformly from [0, n) for the injected jitter
// source. Parameters: n — the exclusive upper bound, always positive when
// called. Returns: the draw.
func defaultJitter(n int64) int64 {
	return rand.Int63n(n)
}
