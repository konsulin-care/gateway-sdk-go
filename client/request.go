package client

import (
	"errors"
	"net/http"
)

// ResponseMeta is the observability summary of one completed gateway
// response: HTTP status, the gateway request id, and the response
// headers. WithResponseMeta captures it on success and failure alike
// (SDK-CLIENT-003), so a caller can correlate a failed call without the
// response body. The Header clone belongs to the capture callback.
type ResponseMeta struct {
	// Status is the HTTP status of the response.
	Status int
	// RequestID is the X-Request-Id response header, verbatim.
	RequestID string
	// Header is a clone of the response headers.
	Header http.Header
}

// CallOption adjusts a single Do call without touching Client state;
// applied per call, e.g. WithResponseMeta. Invalid values (nil option,
// nil callback) fail the call instead of being silently ignored.
type CallOption func(*callConfig) error

// callConfig collects the per-call option values of one Do call.
type callConfig struct {
	metaFns []func(ResponseMeta)
}

// WithResponseMeta registers fn to receive a ResponseMeta for every
// completed gateway response — on success and on failure (as
// *wire.Error) alike — capturing status, request_id and headers.
// Parameters: fn — the capture callback, invoked once per response.
// Returns: a CallOption for Do; a nil fn fails the call, never ignored.
func WithResponseMeta(fn func(ResponseMeta)) CallOption {
	return func(cc *callConfig) error {
		if fn == nil {
			return errors.New("client: WithResponseMeta: callback must not be nil")
		}
		cc.metaFns = append(cc.metaFns, fn)
		return nil
	}
}

// applyCallOptions folds opts into one callConfig.
// Parameters: opts — the per-call options passed to Do. Returns: the
// collected config, or an error for a nil option or invalid value.
func applyCallOptions(opts []CallOption) (callConfig, error) {
	var cc callConfig
	for _, opt := range opts {
		if opt == nil {
			return callConfig{}, errors.New("client: nil call option")
		}
		if err := opt(&cc); err != nil {
			return callConfig{}, err
		}
	}
	return cc, nil
}

// capture invokes every registered meta callback with meta, in
// registration order.
func (cc *callConfig) capture(meta ResponseMeta) {
	for _, fn := range cc.metaFns {
		fn(meta)
	}
}
