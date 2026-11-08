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
// expectations, (5) service matches, (6) raw data within
// maxBoundDataBytes. The iat freshness and nonce replay checks are added
// by the follow-up requirements; ctx, cache, and clock are reserved for
// them and unused here. Errors carry only check facts — never the wrapper
// values, the payload, or the plaintext.
//
// Parameters: ctx carries caller cancellation (reserved for the replay
// cache); compact is the five-segment compact JWE; d is the caller's
// Decrypter whose private key matches the header kid; exp are the
// expected wrapper from/to/service values; cache is the ReplayCache for
// nonce dedupe (reserved); clock is the time source for the iat window
// (reserved).
// Returns: the wrapper data bytes and nil, or nil and an error — never a
// partial accept, never a non-nil payload on rejection.
func OpenBound(_ context.Context, compact string, d Decrypter, exp Expectations, _ wire.ReplayCache, _ func() time.Time) ([]byte, error) {
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
	if len(wrapper.Data) > maxBoundDataBytes {
		return nil, fmt.Errorf(
			"envelope: OpenBound: wrapper data is %d bytes, limit %d",
			len(wrapper.Data), maxBoundDataBytes)
	}
	return wrapper.Data, nil
}
