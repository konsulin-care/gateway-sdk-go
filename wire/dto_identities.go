package wire

// RegisterIdentityRequest is the POST /v1/identities/register body:
// hashed identity fields for one party-local resource.
type RegisterIdentityRequest struct {
	// PartyID is optional and deprecated; when present it must equal
	// the authenticated caller (else 403 GW-PARTY-010).
	PartyID string `json:"party_id,omitempty"`
	// ResourceType is the local resource type (e.g. "patient").
	ResourceType string `json:"resource_type"`
	// LocalResourceID is the party-local resource reference.
	LocalResourceID string `json:"local_resource_id"`
	// EmailHash is a base64 32-byte hash or the "N/A" marker.
	EmailHash string `json:"email_hash"`
	// PhoneHash is a base64 32-byte hash or the "N/A" marker.
	PhoneHash string `json:"phone_hash"`
}

// RegisterIdentityResponse is the 200 body of POST /v1/identities/register.
type RegisterIdentityResponse struct {
	// GlobalKey is the opaque key grouping equivalent identities
	// across parties.
	GlobalKey string `json:"global_key"`
}

// ResolveIdentityRequest is the POST /v1/identities/resolve body: the
// hashed fields to resolve to candidate links.
type ResolveIdentityRequest struct {
	// EmailHash is a base64 32-byte hash or the "N/A" marker.
	EmailHash string `json:"email_hash"`
	// PhoneHash is a base64 32-byte hash or the "N/A" marker.
	PhoneHash string `json:"phone_hash"`
}

// IdentityCandidate is one candidate link returned by resolve: the
// gateway returns candidates only, never an automatic join.
type IdentityCandidate struct {
	// GlobalKey is the shared identity key behind the candidate.
	GlobalKey string `json:"global_key"`
	// PartyID is the party holding the linked resource.
	PartyID string `json:"party_id"`
	// LocalResourceID is that party's local resource reference.
	LocalResourceID string `json:"local_resource_id"`
	// MatchField is "email", "phone", "email+phone" or "link".
	MatchField string `json:"match_field"`
}

// ResolveIdentityResponse is the 200 body of POST /v1/identities/resolve;
// the candidate list is empty (never an error) when the calling party
// holds no matching registered row.
type ResolveIdentityResponse struct {
	// Candidates are the matching identity links (possibly empty).
	Candidates []IdentityCandidate `json:"candidates"`
}

// LinkIdentityRequest is the POST /v1/identities/link body declaring
// equivalence between a global key and a local resource.
type LinkIdentityRequest struct {
	// GlobalKey is the confirmed candidate key.
	GlobalKey string `json:"global_key"`
	// PartyID is optional and deprecated (see RegisterIdentityRequest).
	PartyID string `json:"party_id,omitempty"`
	// LocalResourceID is the party-local resource reference.
	LocalResourceID string `json:"local_resource_id"`
}

// LinkIdentityResponse is the 200 body of POST /v1/identities/link.
type LinkIdentityResponse struct {
	// Linked is true once the equivalence row is written.
	Linked bool `json:"linked"`
}
