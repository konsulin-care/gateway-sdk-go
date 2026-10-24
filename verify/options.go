package verify

import (
	"errors"
	"net/http"
	"time"
)

// Verifier defaults: a 5-minute JWKS TTL, one unknown-kid refetch per
// 30-second global window, and a 24-hour replay retention for webhook_id
// (the gateway re-mints delivery tokens per retry with the same
// webhook_id).
const (
	defaultTTL             = 5 * time.Minute
	defaultRefetchInterval = 30 * time.Second
	defaultReplayRetention = 24 * time.Hour
)

// Verifier verifies inbound gateway tokens against the cached gateway JWKS
// (SDK-VERIFY-001/002) and carries the recipient identity, clock, and replay
// configuration the callback middleware and Ticket checks build on. It is
// safe for concurrent use: the underlying JWKS cache and the in-memory
// replay cache serialize on their own mutexes, and a caller-supplied
// ReplayCache must be concurrency-safe as documented in its interface.
type Verifier struct {
	cache     *jwksCache
	self      string
	clock     func() time.Time
	replay    ReplayCache
	retention time.Duration
}

// config collects the NewVerifier options before any is applied, so option
// order never affects the defaults of options not set.
type config struct {
	client          *http.Client
	ttl             time.Duration
	refetchInterval time.Duration
	clock           func() time.Time
	replay          ReplayCache
	retention       time.Duration
}

// Option configures a Verifier at construction. Options are applied in the
// order given; every option has the documented default when not set.
type Option func(*config) error

// NewVerifier builds a Verifier for the gateway JWKS endpoint jwksURL and
// the recipient identity self (the only aud value Verify accepts; the only
// iss it accepts is the literal "gateway").
//
// Parameters: jwksURL is the gateway JWKS endpoint (must not be empty);
// self is this recipient's party id (must not be empty); opts configure
// HTTP client, cache TTL, refetch window, clock, replay cache, and replay
// retention.
// Returns: the Verifier and nil, or an error for an empty URL/self or a
// rejected option. Never panics. The JWKS document itself is fetched
// lazily on the first Verify.
func NewVerifier(jwksURL, self string, opts ...Option) (*Verifier, error) {
	if jwksURL == "" {
		return nil, errors.New("verify: jwks URL must not be empty")
	}
	if self == "" {
		return nil, errors.New("verify: self (recipient identity) must not be empty")
	}
	cfg := config{
		ttl:             defaultTTL,
		refetchInterval: defaultRefetchInterval,
		clock:           time.Now,
		retention:       defaultReplayRetention,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	if cfg.replay == nil {
		cfg.replay = NewMemoryReplayCache(cfg.clock)
	}
	return &Verifier{
		cache:     newJWKSCache(jwksURL, cfg.client, cfg.ttl, cfg.refetchInterval, cfg.clock),
		self:      self,
		clock:     cfg.clock,
		replay:    cfg.replay,
		retention: cfg.retention,
	}, nil
}

// WithHTTPClient sets the client used to fetch the gateway JWKS. A nil
// client means http.DefaultClient.
//
// Parameters: client fetches the JWKS document.
// Returns: an Option applying it.
func WithHTTPClient(client *http.Client) Option {
	return func(cfg *config) error {
		cfg.client = client
		return nil
	}
}

// WithTTL sets how long a fetched JWKS document is served before a refresh
// (default 5 minutes).
//
// Parameters: ttl must be positive; zero or negative values are rejected.
// Returns: an Option applying it, or an error for a non-positive ttl.
func WithTTL(ttl time.Duration) Option {
	return func(cfg *config) error {
		if ttl <= 0 {
			return errors.New("verify: TTL must be positive")
		}
		cfg.ttl = ttl
		return nil
	}
}

// WithRefetchInterval sets the global rate-limit window inside which at most
// one unknown-kid JWKS refetch runs (default 30 seconds).
//
// Parameters: interval must be positive; zero or negative values are
// rejected.
// Returns: an Option applying it, or an error for a non-positive interval.
func WithRefetchInterval(interval time.Duration) Option {
	return func(cfg *config) error {
		if interval <= 0 {
			return errors.New("verify: refetch interval must be positive")
		}
		cfg.refetchInterval = interval
		return nil
	}
}

// WithClock injects the time source for TTL, skew, and replay-expiry checks
// (default time.Now). Tests inject a deterministic clock; the same clock is
// handed to the default replay cache.
//
// Parameters: clock reads the current time; nil means time.Now.
// Returns: an Option applying it.
func WithClock(clock func() time.Time) Option {
	return func(cfg *config) error {
		if clock != nil {
			cfg.clock = clock
		}
		return nil
	}
}

// WithReplayCache replaces the in-memory default replay cache with a
// caller-supplied implementation (e.g. Redis for multi-instance callers).
//
// Parameters: cache satisfies the ReplayCache interface; nil keeps the
// in-memory default.
// Returns: an Option applying it.
func WithReplayCache(cache ReplayCache) Option {
	return func(cfg *config) error {
		if cache != nil {
			cfg.replay = cache
		}
		return nil
	}
}

// WithReplayRetention sets how long a webhook_id stays reserved beyond the
// token's own exp+60s (default 24 hours), because the gateway re-mints
// delivery tokens per retry with the same webhook_id. jti reservations are
// always bounded by exp+60s and ignore this value.
//
// Parameters: retention must be positive; zero or negative values are
// rejected.
// Returns: an Option applying it, or an error for a non-positive retention.
func WithReplayRetention(retention time.Duration) Option {
	return func(cfg *config) error {
		if retention <= 0 {
			return errors.New("verify: replay retention must be positive")
		}
		cfg.retention = retention
		return nil
	}
}
