package adminboot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// tierResponse is the Bruno success shape of
// POST /v1/admin/parties/{id}/tier: the party id and the applied
// tier, echoing the request body tier.
type tierResponse struct {
	PartyID string `json:"party_id"`
	Tier    string `json:"tier"`
}

// SetTier sets partyID's tier at POST /v1/admin/parties/{id}/tier
// with the admin bearer and returns the tier the gateway applied. A
// non-2xx response surfaces as *wire.Error; the admin bearer is never
// logged.
//
// Parameters: ctx is the call context; bearer is the admin token from
// Login; partyID is the party to retier; tier is the tier to apply
// (e.g. "authorized", "konsulin").
// Returns: the applied tier, or the failure.
func (c *Client) SetTier(ctx context.Context, bearer, partyID, tier string) (string, error) {
	if partyID == "" {
		return "", fmt.Errorf("adminboot: set tier: party id must not be empty")
	}
	payload, err := json.Marshal(map[string]string{"tier": tier})
	if err != nil {
		return "", fmt.Errorf("adminboot: set tier: encode request: %w", err)
	}
	var resp tierResponse
	path := "/v1/admin/parties/" + url.PathEscape(partyID) + "/tier"
	if err := c.post(ctx, path, bearer, payload, &resp); err != nil {
		return "", err
	}
	return resp.Tier, nil
}
