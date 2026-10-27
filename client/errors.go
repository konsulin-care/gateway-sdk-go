package client

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// outcome maps one completed gateway response to what Do returns: the
// *Response on 2xx, or the *wire.Error (SDK-CLIENT-003) parsed from the
// error envelope on any other status. A non-envelope body never panics
// and never fabricates a code — it keeps the status, an empty Code, and
// a bounded hint of the body as Message, so it matches no catalog
// sentinel (fail closed).
// Parameters: resp — the response with its buffered body. Returns: the
// response, or the error.
func outcome(resp *Response) (*Response, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, wire.DecodeError(resp.StatusCode, resp.Body)
	}
	return resp, nil
}

// DecodeInto unmarshals a successful (2xx) response body into out,
// ignoring unknown JSON fields (SDK-WIRE-004, ADR-012): fields added by
// a newer gateway never fail the decode and never disturb the known
// fields. Non-2xx responses never reach decode — Do surfaces them as
// *wire.Error first.
// Parameters: resp — the *Response returned by Do; out — a pointer to
// the destination DTO. Returns: nil on success, or a decode error.
func DecodeInto(resp *Response, out any) error {
	if resp == nil {
		return errors.New("client: DecodeInto: nil response")
	}
	if out == nil {
		return errors.New("client: DecodeInto: nil destination")
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return fmt.Errorf("client: decode response body: %w", err)
	}
	return nil
}
