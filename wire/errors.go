package wire

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Catalog error codes (PRD §9.7 SDK-WIRE-003). The gateway renames some
// codes on the wire; PRD is contract authority for catalog names, so
// both spellings are exported and aliased in errors.Is (see codeAliases).
const (
	// CodeCapabilityDenied is the 403 code for a missing capability grant.
	CodeCapabilityDenied = "capability_denied"
	// CodeIdempotencyInProgress is the PRD catalog code for a 409 whose
	// first request is still in flight (SDK-RETRY-002).
	CodeIdempotencyInProgress = "idempotency_in_progress"
	// CodeIdempotencyInProgressGateway is the gateway's current wire code
	// for the same condition (GW-API-002, renamed after the PRD was
	// written). errors.Is treats it as an alias of
	// CodeIdempotencyInProgress so retry classification works on real
	// traffic.
	CodeIdempotencyInProgressGateway = "GW-API-002"
	// CodeInvalidEnrollmentToken is the 401 code for a replayed, missing,
	// or invalid enrollment token (GW-PARTY-007).
	CodeInvalidEnrollmentToken = "GW-PARTY-007"
)

// codeAliases maps a gateway wire code to its PRD catalog code. Codes
// not present map to themselves; lookup is symmetric in errors.Is so a
// sentinel matches either spelling.
var codeAliases = map[string]string{
	CodeIdempotencyInProgressGateway: CodeIdempotencyInProgress,
}

// Catalog sentinels for errors.Is (PRD §9.7 SDK-WIRE-003). Match is by
// Code equality (plus codeAliases), never by pointer identity, so a
// decoded or wrapped *Error compares against the sentinel:
//
//	if errors.Is(err, wire.ErrCapabilityDenied) { ... }
var (
	// ErrCapabilityDenied matches any *Error with code capability_denied
	// (HTTP 403): a missing grant must surface, never be retried around.
	ErrCapabilityDenied = &Error{
		Code:    CodeCapabilityDenied,
		Message: "party lacks the required capability",
		Status:  http.StatusForbidden,
	}
	// ErrIdempotencyInProgress matches code idempotency_in_progress and
	// its gateway wire alias GW-API-002 (HTTP 409): retryable per
	// SDK-RETRY-002.
	ErrIdempotencyInProgress = &Error{
		Code:    CodeIdempotencyInProgress,
		Message: "idempotency key still in progress",
		Status:  http.StatusConflict,
	}
	// ErrInvalidEnrollmentToken matches code GW-PARTY-007 (HTTP 401): an
	// invalid, replayed, or missing enrollment token.
	ErrInvalidEnrollmentToken = &Error{
		Code:    CodeInvalidEnrollmentToken,
		Message: "invalid enrollment token",
		Status:  http.StatusUnauthorized,
	}
)

// Error is the one error type surfaced by every SDK call
// (SDK-WIRE-003): the gateway error envelope fields plus the HTTP
// status of the response. Use errors.Is against the catalog sentinels
// and errors.As to extract it from an opaque chain.
type Error struct {
	// Code is the gateway catalog code (e.g. capability_denied,
	// GW-PARTY-007); empty when the body was not an error envelope.
	Code string
	// Message is the human-readable text from the envelope (or a bounded
	// raw-body hint when the body was not an envelope).
	Message string
	// RequestID correlates the error with gateway logs; preserved
	// verbatim from the envelope (SDK-CLIENT-003).
	RequestID string
	// Status is the HTTP status of the response that carried the error.
	Status int
}

// maxFallbackMessage bounds the raw-body hint DecodeError keeps when
// the body is not an error envelope (e.g. a proxy HTML page).
const maxFallbackMessage = 512

// errorEnvelope mirrors the gateway error response shape written by
// pkg/errors/response.go WriteError.
type errorEnvelope struct {
	Error *struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

// Error implements the error interface as a single line carrying code,
// status, request id, and message. Never includes secrets beyond the
// gateway-supplied message text.
func (e *Error) Error() string {
	if e == nil {
		return "gateway error: <nil>"
	}
	if e.RequestID != "" {
		return fmt.Sprintf("gateway error: code=%s status=%d request_id=%s: %s",
			e.Code, e.Status, e.RequestID, e.Message)
	}
	return fmt.Sprintf("gateway error: code=%s status=%d: %s",
		e.Code, e.Status, e.Message)
}

// Is reports whether target is a *Error with the same catalog code.
// Codes are compared through codeAliases, so a decoded error carrying
// the gateway's spelling (GW-API-002) matches the PRD-named sentinel
// (idempotency_in_progress) and vice versa. Used by errors.Is.
func (e *Error) Is(target error) bool {
	var t *Error
	if !errors.As(target, &t) || e == nil || t == nil {
		return false
	}
	if e.Code == t.Code {
		return true
	}
	if alias, ok := codeAliases[e.Code]; ok && alias == t.Code {
		return true
	}
	alias, ok := codeAliases[t.Code]
	return ok && alias == e.Code
}

// DecodeError decodes a gateway error envelope
// {error:{code,message,request_id}} into an *Error carrying status, the
// HTTP status of the response that produced body. It never returns nil
// and never panics: when body is not a valid envelope (empty, HTML,
// non-object), the returned *Error keeps Status, leaves Code and
// RequestID empty so it matches no catalog sentinel (fail closed), and
// takes a bounded hint of the raw body as Message.
func DecodeError(status int, body []byte) *Error {
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err == nil && env.Error != nil {
		return &Error{
			Code:      env.Error.Code,
			Message:   env.Error.Message,
			RequestID: env.Error.RequestID,
			Status:    status,
		}
	}
	return &Error{
		Message: fallbackMessage(body),
		Status:  status,
	}
}

// fallbackMessage trims body and bounds it to maxFallbackMessage bytes
// for use as the Message of a non-envelope decode result.
func fallbackMessage(body []byte) string {
	msg := strings.TrimSpace(string(body))
	if len(msg) > maxFallbackMessage {
		msg = msg[:maxFallbackMessage] + "..."
	}
	return msg
}
