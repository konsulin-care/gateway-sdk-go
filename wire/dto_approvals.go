package wire

// MintApprovalRequest is the POST /v1/approvals body: an approval/STS
// mint for a recipient party.
type MintApprovalRequest struct {
	// To is the recipient party id.
	To string `json:"to"`
	// Scope is the allowlisted scope: "referral" or "export:<study>".
	Scope string `json:"scope"`
	// Purpose is the literal purpose string (non-reserved).
	Purpose string `json:"purpose"`
	// TTL is the requested lifetime in seconds; the gateway clamps it
	// to 900 (over-cap clamps, never errors).
	TTL int `json:"ttl,omitempty"`
	// ResearcherHash is an optional base64 32-byte hash or "N/A".
	ResearcherHash string `json:"researcher_hash,omitempty"`
}

// MintApprovalResponse is the 200 body of POST /v1/approvals: the
// minted ks-approval+jwt ticket.
type MintApprovalResponse struct {
	// AccessToken is the minted approval JWT.
	AccessToken string `json:"access_token"`
	// JTI is the ticket's unique id (mirrored in its claims).
	JTI string `json:"jti"`
	// ExpiresAt is the ticket expiry (RFC 3339).
	ExpiresAt string `json:"expires_at"`
}
