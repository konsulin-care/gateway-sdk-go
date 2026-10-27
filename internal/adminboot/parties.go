package adminboot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// CreatePartyRequest is the POST /v1/admin/parties body: the new
// party's organization identity and tier.
type CreatePartyRequest struct {
	// OrgName is the human-readable organization name.
	OrgName string `json:"org_name"`
	// OrgIdentifier is the stable organization identifier.
	OrgIdentifier string `json:"org_identifier"`
	// Tier is the party tier ("authorized", ...).
	Tier string `json:"tier,omitempty"`
}

// createPartyResponse is the Bruno success shape of party creation:
// the new party id in state awaiting_key.
type createPartyResponse struct {
	PartyID string `json:"party_id"`
	State   string `json:"state"`
}

// enrollmentTokenResponse is the Bruno success shape of
// POST /v1/admin/parties/{id}/enrollment-token: the single-use
// enrollment token, bound to the path party id, with its expiry.
type enrollmentTokenResponse struct {
	PartyID         string `json:"party_id"`
	EnrollmentToken string `json:"enrollment_token"`
	ExpiresAt       string `json:"expires_at"`
}

// CreateParty registers a party at POST /v1/admin/parties with the
// admin bearer and returns the created party id. A non-2xx response
// surfaces as *wire.Error; the admin bearer is never logged.
//
// Parameters: ctx is the call context; bearer is the admin token from
// Login; req is the party to create.
// Returns: the created party id, or the failure.
func (c *Client) CreateParty(ctx context.Context, bearer string, req CreatePartyRequest) (string, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("adminboot: create party: encode request: %w", err)
	}
	var resp createPartyResponse
	if err := c.post(ctx, "/v1/admin/parties", bearer, payload, &resp); err != nil {
		return "", err
	}
	if resp.PartyID == "" {
		return "", fmt.Errorf("adminboot: create party: response carried no party id")
	}
	return resp.PartyID, nil
}

// IssueEnrollmentToken requests the single-use enrollment token for
// partyID at POST /v1/admin/parties/{id}/enrollment-token with the
// admin bearer and returns the plaintext token (it appears exactly
// once, in that response). A non-2xx response surfaces as
// *wire.Error; neither the token nor the bearer is ever logged.
//
// Parameters: ctx is the call context; bearer is the admin token from
// Login; partyID is the party the token is issued for.
// Returns: the enrollment token, or the failure.
func (c *Client) IssueEnrollmentToken(ctx context.Context, bearer, partyID string) (string, error) {
	if partyID == "" {
		return "", fmt.Errorf("adminboot: issue enrollment token: party id must not be empty")
	}
	var resp enrollmentTokenResponse
	path := "/v1/admin/parties/" + url.PathEscape(partyID) + "/enrollment-token"
	if err := c.post(ctx, path, bearer, []byte("{}"), &resp); err != nil {
		return "", err
	}
	if resp.EnrollmentToken == "" {
		return "", fmt.Errorf("adminboot: issue enrollment token: response carried no token")
	}
	return resp.EnrollmentToken, nil
}
