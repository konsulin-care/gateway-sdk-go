package gatewaytest

import (
	"encoding/json"
	"net/http"
	"strings"
)

// adminToken is the canned admin bearer token: the fake's login issues
// it on success and every authed admin route accepts exactly it. It is
// a fixed literal, not a verifiable JWT — the admin fake never checks
// signatures, it only surfaces the Bruno response shapes.
const adminToken = "eyJhbGciOiJFZERTQSIsImtpZCI6ImFkbWluLWtleS0xIn0.YWRtaW4tZmFrZQ.c2ln"

// adminPartyID is the canned party id Create Party returns in state
// awaiting_key.
const adminPartyID = "01HZYADMINPARTY00000"

// adminEnrollmentToken is the canned single-use enrollment token Issue
// Enrollment Token returns; like the real route, the plaintext appears
// exactly once, in the response.
const adminEnrollmentToken = "enroll-token-admin-fake-0001"

// AdminOptions configures the opt-in canned admin handlers enabled by
// EnableAdmin.
type AdminOptions struct {
	// Username is the operator username the fake login accepts.
	Username string
	// Password is the operator password the fake login accepts.
	Password string
}

// adminConfig is the locked admin state EnableAdmin installs on a
// Gateway; a nil *adminConfig means the admin fakes are disabled and
// every /v1/admin path stays unmatched (404) as before.
type adminConfig struct {
	username string
	password string
}

// EnableAdmin opts the fake gateway in to the canned admin handlers for
// POST /v1/admin/auth/login (username/password only — the totp field is
// ignored), POST /v1/admin/parties, POST /v1/admin/parties/{id}/
// enrollment-token, the capability grant, and the party revoke, with
// the response shapes of the Bruno admin collection. The login issues
// the canned admin bearer token; the four authed routes accept only
// that token and answer 401 GW-ADMIN-001 without it. Admin paths not in
// that set — and every admin path while disabled — keep answering 404.
//
// Parameters: opts carries the operator credentials the login fake
// accepts. Requests are recorded in Recorded() like party requests.
func (g *Gateway) EnableAdmin(opts AdminOptions) {
	g.mu.Lock()
	g.admin = &adminConfig{username: opts.Username, password: opts.Password}
	g.mu.Unlock()
}

// adminEnabled returns the active admin config, or nil when the admin
// fakes are off.
func (g *Gateway) adminEnabled() *adminConfig {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.admin
}

// serveAdmin serves one request when the admin fakes are enabled and
// the path is one of the five canned admin routes; false falls through
// to the §9.6 route table, where admin paths 404 as before.
func (g *Gateway) serveAdmin(w http.ResponseWriter, r *http.Request, body []byte, cfg *adminConfig) bool {
	if r.Method != http.MethodPost {
		return false
	}
	segs := splitPath(r.URL.Path)
	if !isAdminPath(segs) {
		return false
	}
	switch {
	case isAdminLogin(segs):
		serveAdminLogin(w, body, cfg)
		return true
	case isAdminCreateParty(segs):
		if !adminAuthorized(r) {
			serveAdminUnauthorized(w)
			return true
		}
		serveAdminCreateParty(w)
		return true
	case isAdminPartySubroute(segs):
		if !adminAuthorized(r) {
			serveAdminUnauthorized(w)
			return true
		}
		return serveAdminPartySubroute(w, segs[3], segs[4], body)
	}
	return false
}

// isAdminPath reports whether segments sit under the /v1/admin prefix.
func isAdminPath(segs []string) bool {
	return len(segs) >= 3 && segs[0] == "v1" && segs[1] == "admin"
}

// isAdminLogin reports whether segments are POST /v1/admin/auth/login.
func isAdminLogin(segs []string) bool {
	return len(segs) == 4 && segs[2] == "auth" && segs[3] == "login"
}

// isAdminCreateParty reports whether segments are POST /v1/admin/parties.
func isAdminCreateParty(segs []string) bool {
	return len(segs) == 3 && segs[2] == "parties"
}

// isAdminPartySubroute reports whether segments are a party-scoped admin
// subroute: /v1/admin/parties/{id}/<sub> with a non-empty id.
func isAdminPartySubroute(segs []string) bool {
	return len(segs) == 5 && segs[2] == "parties" && segs[3] != ""
}

// adminAuthorized reports whether the request carries the canned admin
// bearer token issued by the fake login.
func adminAuthorized(r *http.Request) bool {
	return r.Header.Get("Authorization") == "Bearer "+adminToken
}

// serveAdminUnauthorized answers the Bruno "no admin token" 401
// envelope shared by the authed admin routes.
func serveAdminUnauthorized(w http.ResponseWriter) {
	writeBody(w, http.StatusUnauthorized,
		errorEnvelopeBytes("GW-ADMIN-001", "invalid or expired token"))
}

// serveAdminLogin fakes POST /v1/admin/auth/login: an undecodable or
// missing-field body answers 400 GW-ADMIN-002, wrong credentials 401
// GW-ADMIN-001, and correct credentials the Bruno success shape with
// the canned admin token. The totp field is accepted and ignored — the
// fake is username/password only.
func serveAdminLogin(w http.ResponseWriter, body []byte, cfg *adminConfig) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Username == "" || len(req.Password) == 0 {
		writeBody(w, http.StatusBadRequest,
			errorEnvelopeBytes("GW-ADMIN-002", "username and password are required"))
		return
	}
	if req.Username != cfg.username || req.Password != cfg.password {
		writeBody(w, http.StatusUnauthorized,
			errorEnvelopeBytes("GW-ADMIN-001", "invalid credentials"))
		return
	}
	writeBody(w, http.StatusOK, marshalExample(map[string]any{
		"token": adminToken, "token_type": "Bearer", "expires_in": 3600,
	}))
}

// serveAdminCreateParty fakes POST /v1/admin/parties with the Bruno
// success shape: the canned party id in state awaiting_key. Inputs are
// not validated — the fake serves the success path only.
func serveAdminCreateParty(w http.ResponseWriter) {
	writeBody(w, http.StatusOK, marshalExample(map[string]any{
		"party_id": adminPartyID, "state": "awaiting_key",
	}))
}

// serveAdminPartySubroute dispatches one authed party-scoped admin
// subroute; false when the subroute is not canned, so the request falls
// through to the route table and 404s.
func serveAdminPartySubroute(w http.ResponseWriter, partyID, sub string, body []byte) bool {
	switch sub {
	case "enrollment-token":
		serveAdminEnrollmentToken(w, partyID)
	case "capabilities":
		serveAdminGrantCapability(w, partyID, body)
	case "revoke":
		serveAdminRevokeParty(w, partyID)
	default:
		return false
	}
	return true
}

// serveAdminEnrollmentToken fakes POST /v1/admin/parties/{id}/
// enrollment-token: the Bruno success shape binding the canned token to
// the path party id.
func serveAdminEnrollmentToken(w http.ResponseWriter, partyID string) {
	writeBody(w, http.StatusOK, marshalExample(map[string]any{
		"party_id": partyID, "enrollment_token": adminEnrollmentToken,
		"expires_at": "2026-12-31T12:00:00Z",
	}))
}

// serveAdminGrantCapability fakes POST /v1/admin/parties/{id}/
// capabilities: echoes the path party id and the requested capability
// as granted; accept:* ids are direction in, everything else out (the
// Bruno derivation). An undecodable or empty body grants the Bruno doc
// example capability — the fake serves the success path only.
func serveAdminGrantCapability(w http.ResponseWriter, partyID string, body []byte) {
	var req struct {
		Capability string `json:"capability"`
	}
	_ = json.Unmarshal(body, &req)
	if req.Capability == "" {
		req.Capability = "webhook:invoke"
	}
	direction := "out"
	if strings.HasPrefix(req.Capability, "accept:") {
		direction = "in"
	}
	writeBody(w, http.StatusOK, marshalExample(map[string]any{
		"party_id": partyID, "capability": req.Capability,
		"direction": direction, "status": "granted",
	}))
}

// serveAdminRevokeParty fakes POST /v1/admin/parties/{id}/revoke: the
// Bruno success shape, party state revoked.
func serveAdminRevokeParty(w http.ResponseWriter, partyID string) {
	writeBody(w, http.StatusOK, marshalExample(map[string]any{
		"party_id": partyID, "state": "revoked",
	}))
}
