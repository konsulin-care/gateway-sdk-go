package envelope

import (
	"errors"
	"fmt"
	"time"

	"github.com/konsulin-care/gateway-sdk-go/verify"
)

// DefaultMaxAge is the envelope age bound applied when an Expectations
// value leaves MaxAge unset: five minutes.
const DefaultMaxAge = 5 * time.Minute

// MaxMaxAge is the largest age bound an Expectations value may request:
// fifteen minutes. Anything larger is rejected fail-closed.
const MaxMaxAge = 15 * time.Minute

// Expectations are the binding values a bound envelope must carry for an
// open to succeed: From is the sending party (token sub), To the intended
// recipient (the token's sole audience), Service the delivery's service,
// and MaxAge the oldest acceptable wrapper iat — zero means DefaultMaxAge,
// resolved by effectiveMaxAge.
type Expectations struct {
	// From is the expected wrapper "from": the delivery token's sub.
	From string
	// To is the expected wrapper "to": the delivery token's single aud entry.
	To string
	// Service is the expected wrapper "service": the delivery's service claim.
	Service string
	// MaxAge bounds how old the wrapper iat may be; zero means DefaultMaxAge.
	MaxAge time.Duration
}

// ExpectationsFromClaims derives bound-envelope expectations from the
// already-verified delivery claims, so callers never pass values the token
// did not cover (SDKP-001). It fails closed when the claims carry an empty
// service or an audience count other than one.
//
// Parameters: c are the verified claims of the delivery token.
// Returns: the derived expectations and nil, or a zero value and an error
// naming the rejected claim shape.
func ExpectationsFromClaims(c verify.Claims) (Expectations, error) {
	if c.Service == "" {
		return Expectations{}, errors.New("envelope: ExpectationsFromClaims: claims carry no service")
	}
	if len(c.Audience) != 1 {
		return Expectations{}, fmt.Errorf("envelope: ExpectationsFromClaims: want exactly one audience, got %d", len(c.Audience))
	}
	return Expectations{From: c.Sub, To: c.Audience[0], Service: c.Service}, nil
}

// effectiveMaxAge resolves the age bound OpenBound enforces against the
// wrapper iat: a zero MaxAge means DefaultMaxAge, and a value below zero
// or above MaxMaxAge is rejected fail-closed so no caller can widen the
// window past fifteen minutes.
//
// Returns: the effective age bound and nil, or zero and an error naming
// the rejected MaxAge.
func (e Expectations) effectiveMaxAge() (time.Duration, error) {
	switch {
	case e.MaxAge == 0:
		return DefaultMaxAge, nil
	case e.MaxAge < 0:
		return 0, fmt.Errorf("envelope: effective MaxAge must not be negative, got %s", e.MaxAge)
	case e.MaxAge > MaxMaxAge:
		return 0, fmt.Errorf("envelope: effective MaxAge must not exceed %s, got %s", MaxMaxAge, e.MaxAge)
	default:
		return e.MaxAge, nil
	}
}
