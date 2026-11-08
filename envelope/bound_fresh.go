package envelope

import (
	"fmt"
	"time"
)

// maxIatFutureSkew is how far ahead of the clock the wrapper iat may sit
// before OpenBound rejects it: 60 seconds (SDKP-001).
const maxIatFutureSkew = 60 * time.Second

// checkBoundIat enforces the SDKP-001 iat freshness window, step 6 of
// OpenBound: the wrapper iat must be no older than maxAge and no more
// than maxIatFutureSkew ahead of now, so a stale or future-dated wrapper
// fails closed. An iat exactly maxAge old, or exactly maxIatFutureSkew
// ahead, is still accepted — only values beyond the bounds are rejected.
//
// Parameters: iat is the wrapper issued-at in Unix seconds; maxAge is the
// effective age bound from Expectations.effectiveMaxAge; now is the
// caller's clock reading.
// Returns: nil when the iat sits inside the window, or an error naming
// the violated bound — never the iat value itself.
func checkBoundIat(iat int64, maxAge time.Duration, now time.Time) error {
	issuedAt := time.Unix(iat, 0)
	if age := now.Sub(issuedAt); age > maxAge {
		return fmt.Errorf(
			"envelope: OpenBound: wrapper iat is older than the freshness window (max %s)", maxAge)
	} else if age < -maxIatFutureSkew {
		return fmt.Errorf(
			"envelope: OpenBound: wrapper iat is more than %s in the future", maxIatFutureSkew)
	}
	return nil
}
