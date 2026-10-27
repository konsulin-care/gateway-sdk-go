package client

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// config collects all option values first, so option order never affects
// defaults.
type config struct {
	baseURL    string
	partyID    string
	signer     crypto.Signer
	httpClient *http.Client
	insecure   bool
	replay     ReplayCache
	logger     *slog.Logger
	retry      RetryPolicy
}

// Option configures a Client at construction; an invalid value fails New.
type Option func(*config) error

// WithBaseURL sets the required gateway base URL (SDK-CLIENT-C01): https, or
// http with WithInsecureTransport on a loopback host.
// Parameters: raw (absolute base URL). Returns: an Option; bad URL fails New.
func WithBaseURL(raw string) Option {
	return func(cfg *config) error {
		cfg.baseURL = raw
		return nil
	}
}

// WithSigner injects the party signing key (iss = party id, aud = gateway,
// typ ks-party+jwt, fresh jti per attempt; custody: caller, ADR-006).
// Returns: an Option; empty partyID or nil key fails New.
func WithSigner(partyID string, key crypto.Signer) Option {
	return func(cfg *config) error {
		if partyID == "" || key == nil {
			return errors.New("client: WithSigner: party id and signer must not be empty")
		}
		cfg.partyID = partyID
		cfg.signer = key
		return nil
	}
}

// WithHTTPClient injects the *http.Client every request is issued through
// (default http.DefaultClient). Returns: an Option; nil fails New.
func WithHTTPClient(hc *http.Client) Option {
	return func(cfg *config) error {
		if hc == nil {
			return errors.New("client: WithHTTPClient: http client must not be nil")
		}
		cfg.httpClient = hc
		return nil
	}
}

// WithInsecureTransport opts http base URLs in (transport guard): only
// loopback hosts (127.0.0.1, ::1, localhost) are accepted. Returns: an Option.
func WithInsecureTransport() Option {
	return func(cfg *config) error {
		cfg.insecure = true
		return nil
	}
}

// WithReplayCache injects the replay cache used by the retry path (default:
// none). Returns: an Option; nil fails New.
func WithReplayCache(rc ReplayCache) Option {
	return func(cfg *config) error {
		if rc == nil {
			return errors.New("client: WithReplayCache: replay cache must not be nil")
		}
		cfg.replay = rc
		return nil
	}
}

// WithLogger injects the *slog.Logger for request logging: method, path,
// status, request_id only — never bodies, tokens, or keys (PRD §8). Default
// slog.Default(). Parameters: l. Returns: an Option; nil fails New, not
// ignored.
func WithLogger(l *slog.Logger) Option {
	return func(cfg *config) error {
		if l == nil {
			return errors.New("client: WithLogger: logger must not be nil")
		}
		cfg.logger = l
		return nil
	}
}

// WithRetry sets the bounded retry policy (SDK-RETRY-001); default is one
// attempt; retry re-signs with a fresh jti. Returns: an Option; a policy
// with attempts below 1 or negative delays fails New.
func WithRetry(p RetryPolicy) Option {
	return func(cfg *config) error {
		if p.MaxAttempts < 1 || p.BaseDelay < 0 || p.MaxDelay < 0 {
			return fmt.Errorf("client: WithRetry: invalid policy %+v: attempts >= 1, non-negative delays", p)
		}
		cfg.retry = p
		return nil
	}
}

// RetryPolicy bounds one logical call (SDK-RETRY-002): MaxAttempts counts the
// first attempt (1 disables retry); delays are backoff bounds with jitter.
type RetryPolicy struct {
	MaxAttempts int           // total attempts, minimum 1
	BaseDelay   time.Duration // backoff before the second attempt
	MaxDelay    time.Duration // cap on one backoff delay
}

// ReplayCache atomically deduplicates retry-scope keys; matches
// verify.ReplayCache so one implementation satisfies both.
type ReplayCache interface {
	// Check reserves (scope, key) until until: true when fresh, false on
	// replay, or an error — callers deny on error.
	Check(ctx context.Context, scope, key string, until time.Time) (bool, error)
	// Release frees the (scope, key) reservation; unreserved pairs are a
	// no-op.
	Release(ctx context.Context, scope, key string) error
}

// transportURL parses raw and applies the guard: https always; http only
// with insecure opted in, loopback only.
func transportURL(raw string, insecure bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("client: WithBaseURL %q: %w", raw, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("client: WithBaseURL %q: scheme must be https (or http with WithInsecureTransport)", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("client: WithBaseURL %q: missing host", raw)
	}
	if u.Scheme == "http" && (!insecure || !isLoopbackHost(u.Hostname())) {
		return nil, fmt.Errorf("client: WithBaseURL %q: http requires WithInsecureTransport and a loopback host (127.0.0.1, ::1, localhost)", raw)
	}
	return u, nil
}

// isLoopbackHost reports "localhost" or a loopback IP (127.0.0.0/8, ::1).
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
