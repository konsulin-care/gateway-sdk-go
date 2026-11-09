package envelope

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// minNonceReplayRetention is the floor on how long OpenBound reserves a
// (from, nonce) pair in the ReplayCache: ten minutes (SDKP-001).
const minNonceReplayRetention = 10 * time.Minute

// maxNonceChars is the largest wrapper nonce OpenBound accepts: 64
// characters. An empty or longer nonce fails closed before the
// ReplayCache is ever consulted (SDKP-001 nonce format rules).
const maxNonceChars = 64

// errNonceReplay denies a bound envelope whose (from, nonce) pair is
// already reserved: the ReplayCache reported the pair as seen
// (SDKP-001). It carries only the check fact, never the wrapper values.
var errNonceReplay = errors.New("envelope: OpenBound: nonce replay detected")

// nonceReplayKey builds the ReplayCache key for the nonce check from the
// wrapper's from and nonce, joined by a separator that cannot occur in
// either value, so distinct (from, nonce) pairs never collide.
//
// Parameters: from is the wrapper sender; nonce is the wrapper nonce.
// Returns: the composite key.
func nonceReplayKey(from, nonce string) string {
	return from + "\x00" + nonce
}

// checkNonceFormat enforces the SDKP-001 nonce format rules: an empty
// nonce or one longer than 64 characters fails closed before any cache
// consultation. The error names only the check fact, never the nonce.
//
// Parameters: nonce is the wrapper nonce.
// Returns: nil when the nonce is within bounds, or an error.
func checkNonceFormat(nonce string) error {
	if nonce == "" {
		return errors.New("envelope: OpenBound: nonce is empty")
	}
	if len(nonce) > maxNonceChars {
		return fmt.Errorf("envelope: OpenBound: nonce exceeds %d chars", maxNonceChars)
	}
	return nil
}

// checkNonceReplay enforces the SDKP-001 nonce replay check, step 7 of
// OpenBound: it first validates the nonce format, then atomically reserves (wire.ScopeNonce, from+nonce) in the
// caller's ReplayCache until now + max(10 min, maxAge + 60 s) — the
// freshness window plus the future-skew bound covers every wrapper the
// iat check could still accept, and ten minutes is the ADDENDUM floor.
// A replayed pair denies with errNonceReplay; any cache error denies
// fail-closed. A nil cache opts out of dedupe entirely (no reservation).
//
// Parameters: ctx carries caller cancellation into the cache; cache is
// the caller's ReplayCache, nil to skip; from and nonce are the wrapper
// values forming the key; maxAge is the effective freshness bound; now is
// the clock reading the reservation is measured from.
// Returns: nil when the pair was fresh (reserved), or an error naming the
// replay or the cache failure — never the wrapper values.
func checkNonceReplay(ctx context.Context, cache wire.ReplayCache, from, nonce string, maxAge time.Duration, now time.Time) error {
	if err := checkNonceFormat(nonce); err != nil {
		return err
	}
	if cache == nil {
		return nil
	}
	retention := max(minNonceReplayRetention, maxAge+maxIatFutureSkew)
	fresh, err := cache.Check(ctx, wire.ScopeNonce, nonceReplayKey(from, nonce), now.Add(retention))
	if err != nil {
		return fmt.Errorf("envelope: OpenBound: nonce reservation: %w", err)
	}
	if !fresh {
		return errNonceReplay
	}
	return nil
}
