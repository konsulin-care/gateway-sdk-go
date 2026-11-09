package envelope

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// OpenBound opens a bound envelope sealed by SealBound and enforces the
// SDKP-001 wrapper checks in the normative order, failing closed with nil
// data on the first failure: (1) the JWE decrypt per Open, (2) wrapper v
// supported, (3) to equals the expectations, (4) from equals the
// expectations, (5) service matches, (6) iat no older than the effective
// MaxAge and no more than 60 s in the future, (7) the (from, nonce) pair
// is fresh in the ReplayCache under wire.ScopeNonce, reserved until
// now + max(10 min, MaxAge + 60 s), (8) raw data within
// maxBoundDataBytes. Errors carry only check facts — never the wrapper
// values, the payload, or the plaintext.
//
// Parameters: ctx carries caller cancellation into the replay cache;
// compact is the five-segment compact JWE; d is the caller's Decrypter
// whose private key matches the header kid; exp are the expected wrapper
// from/to/service values and the iat freshness MaxAge; cache is the
// ReplayCache for nonce dedupe (nil skips the check); clock is the time
// source the iat window and the replay reservation are measured against.
// Returns: the wrapper data bytes and nil, or nil and an error — never a
// partial accept, never a non-nil payload on rejection.
func OpenBound(ctx context.Context, compact string, d Decrypter, exp Expectations, cache wire.ReplayCache, clock func() time.Time) ([]byte, error) {
	plaintext, err := Open(compact, d)
	if err != nil {
		return nil, err
	}
	var wrapper boundWrapper
	if err := json.Unmarshal(plaintext, &wrapper); err != nil {
		return nil, fmt.Errorf("envelope: OpenBound: wrapper decode: %w", err)
	}
	if wrapper.V != boundVersion {
		return nil, fmt.Errorf(
			"envelope: OpenBound: unsupported wrapper v %d (want %d)", wrapper.V, boundVersion)
	}
	if wrapper.To != exp.To {
		return nil, errors.New("envelope: OpenBound: wrapper to does not match expectations")
	}
	if wrapper.From != exp.From {
		return nil, errors.New("envelope: OpenBound: wrapper from does not match expectations")
	}
	if wrapper.Service != exp.Service {
		return nil, errors.New("envelope: OpenBound: wrapper service does not match expectations")
	}
	maxAge, err := exp.effectiveMaxAge()
	if err != nil {
		return nil, err
	}
	now := clock()
	if err := checkBoundIat(wrapper.Iat, maxAge, now); err != nil {
		return nil, err
	}
	if err := checkNonceReplay(ctx, cache, wrapper.From, wrapper.Nonce, maxAge, now); err != nil {
		return nil, err
	}
	if len(wrapper.Data) > maxBoundDataBytes {
		return nil, fmt.Errorf(
			"envelope: OpenBound: wrapper data is %d bytes, limit %d",
			len(wrapper.Data), maxBoundDataBytes)
	}
	return wrapper.Data, nil
}
