package envelope

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/verify"
)

// TestExpectationsFromClaimsMapsClaims pins the SDKP-001 mapping from
// already-verified delivery claims to bound-envelope expectations: sub
// becomes From, the single audience entry becomes To, service becomes
// Service, and MaxAge stays zero for later resolution.
func TestExpectationsFromClaimsMapsClaims(t *testing.T) {
	got, err := ExpectationsFromClaims(verify.Claims{
		Sub:      "party-seller",
		Audience: []string{"party-recipient"},
		Service:  "consultation",
	})
	require.NoError(t, err)
	assert.Equal(t, Expectations{
		From:    "party-seller",
		To:      "party-recipient",
		Service: "consultation",
	}, got)
}

// TestExpectationsFromClaimsRejects pins the fail-closed derivation:
// claims with an empty service or an audience count other than one are
// rejected, so expectations never carry values the token did not cover.
func TestExpectationsFromClaimsRejects(t *testing.T) {
	cases := map[string]verify.Claims{
		"empty service": {
			Sub:      "party-seller",
			Audience: []string{"party-recipient"},
		},
		"no audience": {
			Sub:     "party-seller",
			Service: "consultation",
		},
		"two audiences": {
			Sub:      "party-seller",
			Audience: []string{"party-recipient", "party-other"},
			Service:  "consultation",
		},
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ExpectationsFromClaims(claims)
			require.Error(t, err)
			assert.Zero(t, got)
		})
	}
}

// TestEffectiveMaxAge pins the SDKP-001 age bound used by OpenBound:
// DefaultMaxAge is five minutes, MaxMaxAge is fifteen minutes, a zero
// MaxAge resolves to the default, and a MaxAge above the maximum or below
// zero fails closed.
func TestEffectiveMaxAge(t *testing.T) {
	assert.Equal(t, 5*time.Minute, DefaultMaxAge)
	assert.Equal(t, 15*time.Minute, MaxMaxAge)

	t.Run("zero resolves to default", func(t *testing.T) {
		got, err := Expectations{}.effectiveMaxAge()
		require.NoError(t, err)
		assert.Equal(t, DefaultMaxAge, got)
	})

	t.Run("explicit value within bounds kept", func(t *testing.T) {
		got, err := Expectations{MaxAge: MaxMaxAge}.effectiveMaxAge()
		require.NoError(t, err)
		assert.Equal(t, MaxMaxAge, got)
	})

	t.Run("above maximum rejected", func(t *testing.T) {
		_, err := Expectations{MaxAge: MaxMaxAge + time.Second}.effectiveMaxAge()
		require.Error(t, err)
	})

	t.Run("negative rejected", func(t *testing.T) {
		_, err := Expectations{MaxAge: -time.Second}.effectiveMaxAge()
		require.Error(t, err)
	})
}
