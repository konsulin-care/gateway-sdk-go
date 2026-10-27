package conformance

import (
	"errors"
	"time"
)

// Config is the conformance runner configuration: the target gateway,
// the operator bootstrap credentials, and the result-callback receiver
// bind address. The operator password is a secret — it is read from
// the environment only and never printed (PRD §8).
type Config struct {
	// BaseURL is the live gateway base URL (scheme://host[:port]).
	BaseURL string
	// OperatorUser is the operator username the bootstrap case logs
	// in with.
	OperatorUser string
	// OperatorPass is the operator password. It is read from the
	// CONFORMANCE_OPERATOR_PASSWORD environment variable only — the
	// command deliberately exposes no password flag.
	OperatorPass string
	// CallbackAddr is the host:port the plain-HTTP result-callback
	// receiver binds; empty selects an ephemeral loopback listener.
	CallbackAddr string
	// Timeout bounds each case individually; zero selects the
	// package default (defaultCaseTimeout).
	Timeout time.Duration
}

// Validate reports whether every required configuration value is set.
// It returns nil for a complete config, or a usage error naming the
// first missing value. The error text carries field names only, never
// any config value, so the operator password cannot leak through it.
//
// Returns: nil for a complete config, otherwise a usage error.
func (c *Config) Validate() error {
	if c == nil || c.BaseURL == "" {
		return errors.New("conformance: missing base URL: pass -base-url or set CONFORMANCE_BASE_URL")
	}
	if c.OperatorUser == "" {
		return errors.New("conformance: missing operator user: pass -operator-user or set CONFORMANCE_OPERATOR_USER")
	}
	if c.OperatorPass == "" {
		return errors.New("conformance: missing operator password: set CONFORMANCE_OPERATOR_PASSWORD")
	}
	return nil
}

// timeout returns the per-case bound, selecting defaultCaseTimeout
// when the config leaves it unset.
func (c *Config) timeout() time.Duration {
	if c != nil && c.Timeout > 0 {
		return c.Timeout
	}
	return defaultCaseTimeout
}
