package envelope

import (
	"context"
	"crypto/ecdh"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sealBoundIat seals the shared payload through SealBound with the
// wrapper iat pinned to iat, so freshness tests control the sealed
// timestamp exactly instead of racing the wall clock.
func sealBoundIat(t *testing.T, recipient *ecdh.PrivateKey, iat time.Time) string {
	t.Helper()
	binding := boundBinding()
	binding.IssuedAt = iat
	compact, err := SealBound(pepperShapedPayload(), "bound-kid", recipient.PublicKey(), binding)
	require.NoError(t, err)
	return compact
}

// TestOpenBoundIatFreshness pins the SDKP-001 iat freshness check
// (OpenBound step 6): with the default MaxAge an iat 4m59s old is
// accepted and an iat 5m01s old is rejected, an iat more than 60 seconds
// in the future is rejected, and with MaxAge 10 minutes an iat 8 minutes
// old is accepted. The clock is frozen at a whole-second instant so every
// window boundary is exact.
func TestOpenBoundIatFreshness(t *testing.T) {
	recipient := newRecipient(t)
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	cases := []struct {
		name    string
		iat     time.Time
		maxAge  time.Duration
		wantErr bool
	}{
		{name: "default MaxAge accepts iat 4m59s old", iat: now.Add(-4*time.Minute - 59*time.Second)},
		{name: "default MaxAge rejects iat 5m01s old", iat: now.Add(-5*time.Minute - time.Second), wantErr: true},
		{name: "rejects iat 61s in the future", iat: now.Add(61 * time.Second), wantErr: true},
		{name: "MaxAge 10m accepts iat 8m old", iat: now.Add(-8 * time.Minute), maxAge: 10 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compact := sealBoundIat(t, recipient, tc.iat)
			exp := boundExpectations()
			exp.MaxAge = tc.maxAge

			data, err := OpenBound(context.Background(), compact, recipient, exp, nil, clock)
			if tc.wantErr {
				assert.Error(t, err, "an iat outside the freshness window must be rejected")
				assert.Nil(t, data, "a rejected wrapper must return nil data")
				return
			}
			require.NoError(t, err, "an iat inside the freshness window must be accepted")
			assert.Equal(t, pepperShapedPayload(), data,
				"an accepted wrapper must return its payload bytes")
		})
	}
}
