package wire

import "net/http"

// Disposition is the normative client action for a gateway error code:
// what a caller must do with a response carrying that code. Values are
// transcribed verbatim from the gateway Error catalog's "Client action"
// column (contract authority: Bruno opencollection.yml §Error catalog)
// and are the input to retry classification (SDK-RETRY-002/003).
type Disposition string

// The four client actions the gateway Error catalog defines.
const (
	// DispositionRetry marks a condition a later attempt may succeed
	// on: the caller may retry with backoff (SDK-RETRY-002).
	DispositionRetry Disposition = "retry"
	// DispositionFixRequest marks a wrong request the caller must
	// correct; never retried as-is (SDK-RETRY-003).
	DispositionFixRequest Disposition = "fix request"
	// DispositionStop marks a condition that must not be retried: it
	// needs external action before the request can succeed
	// (SDK-RETRY-003).
	DispositionStop Disposition = "stop"
	// DispositionReAuthenticate marks a condition cleared only by a
	// fresh token or credential; never retried with the old one
	// (SDK-RETRY-003).
	DispositionReAuthenticate Disposition = "re-authenticate"
)

// CodeEntry is one row of the gateway Error catalog: the stable wire
// code, the HTTP status the gateway answers with, and the normative
// disposition (client action) for that code. Both status and
// disposition are normative in the gateway catalog — the HTTP status
// is derived from the code, and the disposition is the only place the
// right client action is described.
type CodeEntry struct {
	// Code is the stable machine-readable wire code (e.g. GW-PARTY-010).
	Code string
	// Status is the normative HTTP status the gateway returns with Code.
	Status int
	// Disposition is the normative client action for Code.
	Disposition Disposition
}

// codeCatalog is the gateway Error catalog as data: every GW-* wire
// code with its normative status and disposition, transcribed from
// Bruno opencollection.yml §Error catalog and grouped by plane in
// catalog order. Reserved rows the gateway defines but no live
// endpoint emits yet are included so a future response still
// classifies. Both halves are normative; a mismatch is a gateway-side
// contract break, not an SDK choice.
var codeCatalog = []CodeEntry{
	// GW-PARTY — Registry/Resolver plane
	{Code: "GW-PARTY-001", Status: http.StatusNotFound, Disposition: DispositionFixRequest},
	{Code: "GW-PARTY-002", Status: http.StatusForbidden, Disposition: DispositionStop},
	{Code: "GW-PARTY-003", Status: http.StatusConflict, Disposition: DispositionFixRequest},
	{Code: "GW-PARTY-004", Status: http.StatusBadRequest, Disposition: DispositionFixRequest},
	{Code: "GW-PARTY-005", Status: http.StatusNotFound, Disposition: DispositionFixRequest},
	{Code: "GW-PARTY-006", Status: http.StatusConflict, Disposition: DispositionFixRequest},
	{Code: "GW-PARTY-007", Status: http.StatusUnauthorized, Disposition: DispositionFixRequest},
	{Code: "GW-PARTY-008", Status: http.StatusForbidden, Disposition: DispositionFixRequest},
	{Code: "GW-PARTY-009", Status: http.StatusBadGateway, Disposition: DispositionRetry},
	{Code: "GW-PARTY-010", Status: http.StatusForbidden, Disposition: DispositionFixRequest},
	{Code: "GW-PARTY-011", Status: http.StatusForbidden, Disposition: DispositionFixRequest},
	// GW-IDX — Identity plane
	{Code: "GW-IDX-001", Status: http.StatusBadRequest, Disposition: DispositionFixRequest},
	{Code: "GW-IDX-002", Status: http.StatusNotFound, Disposition: DispositionFixRequest},
	{Code: "GW-IDX-010", Status: http.StatusNotFound, Disposition: DispositionFixRequest},
	{Code: "GW-IDX-011", Status: http.StatusTooManyRequests, Disposition: DispositionRetry},
	// GW-STS — Ticket/Approval plane
	{Code: "GW-STS-001", Status: http.StatusBadRequest, Disposition: DispositionFixRequest},
	{Code: "GW-STS-002", Status: http.StatusGone, Disposition: DispositionStop},
	{Code: "GW-STS-003", Status: http.StatusForbidden, Disposition: DispositionFixRequest},
	{Code: "GW-STS-004", Status: http.StatusForbidden, Disposition: DispositionFixRequest},
	{Code: "GW-STS-005", Status: http.StatusTooManyRequests, Disposition: DispositionRetry},
	// GW-PAY — Money plane
	{Code: "GW-PAY-001", Status: http.StatusInternalServerError, Disposition: DispositionRetry},
	{Code: "GW-PAY-002", Status: http.StatusNotFound, Disposition: DispositionFixRequest},
	{Code: "GW-PAY-003", Status: http.StatusUnauthorized, Disposition: DispositionStop},
	{Code: "GW-PAY-004", Status: http.StatusNotFound, Disposition: DispositionFixRequest},
	{Code: "GW-PAY-005", Status: http.StatusNotFound, Disposition: DispositionFixRequest},
	{Code: "GW-PAY-006", Status: http.StatusBadRequest, Disposition: DispositionFixRequest},
	{Code: "GW-PAY-007", Status: http.StatusBadGateway, Disposition: DispositionRetry},
	// GW-HOOK — Integration plane
	{Code: "GW-HOOK-001", Status: http.StatusNotFound, Disposition: DispositionFixRequest},
	{Code: "GW-HOOK-002", Status: http.StatusInternalServerError, Disposition: DispositionRetry},
	{Code: "GW-HOOK-003", Status: http.StatusBadGateway, Disposition: DispositionRetry},
	{Code: "GW-HOOK-004", Status: http.StatusNotFound, Disposition: DispositionFixRequest},
	{Code: "GW-HOOK-005", Status: http.StatusGatewayTimeout, Disposition: DispositionRetry},
	{Code: "GW-HOOK-006", Status: http.StatusPaymentRequired, Disposition: DispositionStop},
	{Code: "GW-HOOK-007", Status: http.StatusUnauthorized, Disposition: DispositionReAuthenticate},
	{Code: "GW-HOOK-008", Status: http.StatusUnprocessableEntity, Disposition: DispositionFixRequest},
	{Code: "GW-HOOK-009", Status: http.StatusServiceUnavailable, Disposition: DispositionRetry},
	// GW-ADMIN — Operator plane
	{Code: "GW-ADMIN-001", Status: http.StatusUnauthorized, Disposition: DispositionReAuthenticate},
	{Code: "GW-ADMIN-002", Status: http.StatusBadRequest, Disposition: DispositionFixRequest},
	{Code: "GW-ADMIN-003", Status: http.StatusTooManyRequests, Disposition: DispositionRetry},
	{Code: "GW-ADMIN-004", Status: http.StatusUnauthorized, Disposition: DispositionReAuthenticate},
	{Code: "GW-ADMIN-005", Status: http.StatusUnauthorized, Disposition: DispositionReAuthenticate},
	// GW-API — Cross-cutting transport
	{Code: "GW-API-001", Status: http.StatusRequestEntityTooLarge, Disposition: DispositionFixRequest},
	{Code: "GW-API-002", Status: http.StatusConflict, Disposition: DispositionRetry},
	{Code: "GW-API-003", Status: http.StatusInternalServerError, Disposition: DispositionRetry},
	// GW-RATE — Rate limiting
	{Code: "GW-RATE-001", Status: http.StatusTooManyRequests, Disposition: DispositionRetry},
}

// codeIndex indexes codeCatalog by code so lookup is O(1). It is built
// once from the catalog, so the index and the table can never disagree.
var codeIndex = func() map[string]CodeEntry {
	idx := make(map[string]CodeEntry, len(codeCatalog))
	for _, entry := range codeCatalog {
		idx[entry.Code] = entry
	}
	return idx
}()

// LookupCode returns the catalog entry for a gateway error code: the
// entry with its normative HTTP status and disposition plus true on a
// hit, the zero CodeEntry and false for any code the gateway catalog
// does not define (callers fail closed on a miss).
func LookupCode(code string) (CodeEntry, bool) {
	entry, ok := codeIndex[code]
	return entry, ok
}

// Codes returns the full gateway error catalog — every GW-* code with
// its HTTP status and normative disposition — as a fresh copy.
// Mutating the returned slice does not affect the package.
func Codes() []CodeEntry {
	out := make([]CodeEntry, len(codeCatalog))
	copy(out, codeCatalog)
	return out
}
