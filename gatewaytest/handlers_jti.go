package gatewaytest

import "net/http"

// EnforceSingleUsePartyJTI opts the fake gateway into single-use party
// jti enforcement: from then on, every request on a §9.6 route carrying
// a decodable bearer-token jti claim is recorded on first sight, and any
// later request on a §9.6 route carrying the same jti answers 401 with
// the GW-ADMIN-004 error envelope. The jti claim is decoded WITHOUT
// signature verification (like RecordedRequest.PartyJTI); the fake
// surfaces replay shape, not token validity. Requests without a
// decodable bearer jti are never denied, admin fakes are unaffected, and
// a queued scripted step is still served ahead of the check. Enforcement
// is opt-in and off by default.
func (g *Gateway) EnforceSingleUsePartyJTI() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.jtiEnforce = true
	if g.jtiSeen == nil {
		g.jtiSeen = make(map[string]struct{})
	}
}

// serveJTIReplay applies single-use jti enforcement to one §9.6 route
// request and reports whether it wrote the response: enforcement off or
// no decodable bearer jti passes through (false); a fresh jti is
// recorded and passes (false); an already-seen jti answers 401
// GW-ADMIN-004 (true).
func (g *Gateway) serveJTIReplay(w http.ResponseWriter, r *http.Request) bool {
	g.mu.Lock()
	enforce := g.jtiEnforce
	g.mu.Unlock()
	if !enforce {
		return false
	}
	jti := bearerJTI(r.Header.Get("Authorization"))
	if jti == "" {
		return false
	}
	g.mu.Lock()
	_, seen := g.jtiSeen[jti]
	if !seen {
		g.jtiSeen[jti] = struct{}{}
	}
	g.mu.Unlock()
	if seen {
		writeBody(w, http.StatusUnauthorized,
			errorEnvelopeBytes("GW-ADMIN-004", "token replayed: jti already used"))
		return true
	}
	return false
}
