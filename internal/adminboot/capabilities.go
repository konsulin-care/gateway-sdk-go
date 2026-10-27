package adminboot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// grantCapabilityResponse is the Bruno success shape of
// POST /v1/admin/parties/{id}/capabilities: the granted capability
// with its direction and granted status.
type grantCapabilityResponse struct {
	PartyID    string `json:"party_id"`
	Capability string `json:"capability"`
	Direction  string `json:"direction"`
	Status     string `json:"status"`
}

// revokePartyResponse is the Bruno success shape of
// POST /v1/admin/parties/{id}/revoke: the party in state revoked.
type revokePartyResponse struct {
	PartyID string `json:"party_id"`
	State   string `json:"state"`
}

// GrantCapabilities grants each capability to partyID at
// POST /v1/admin/parties/{id}/capabilities with the admin bearer —
// one request per capability, in order, stopping at the first
// failure. A non-2xx response surfaces as *wire.Error; the admin
// bearer is never logged.
//
// Parameters: ctx is the call context; bearer is the admin token from
// Login; partyID is the grantee party; capabilities are the capability
// ids to grant (e.g. wire.CapabilityWebhookInvoke).
// Returns: nil when every capability is granted, or the first
// failure.
func (c *Client) GrantCapabilities(ctx context.Context, bearer, partyID string, capabilities ...string) error {
	if partyID == "" {
		return fmt.Errorf("adminboot: grant capabilities: party id must not be empty")
	}
	path := "/v1/admin/parties/" + url.PathEscape(partyID) + "/capabilities"
	for _, capability := range capabilities {
		payload, err := json.Marshal(map[string]string{"capability": capability})
		if err != nil {
			return fmt.Errorf("adminboot: grant capabilities: encode request: %w", err)
		}
		var resp grantCapabilityResponse
		if err := c.post(ctx, path, bearer, payload, &resp); err != nil {
			return err
		}
	}
	return nil
}

// RevokeParty revokes partyID at POST /v1/admin/parties/{id}/revoke
// with the admin bearer. A non-2xx response surfaces as *wire.Error;
// the admin bearer is never logged.
//
// Parameters: ctx is the call context; bearer is the admin token from
// Login; partyID is the party to revoke.
// Returns: nil on success, or the failure.
func (c *Client) RevokeParty(ctx context.Context, bearer, partyID string) error {
	if partyID == "" {
		return fmt.Errorf("adminboot: revoke party: party id must not be empty")
	}
	var resp revokePartyResponse
	path := "/v1/admin/parties/" + url.PathEscape(partyID) + "/revoke"
	return c.post(ctx, path, bearer, []byte("{}"), &resp)
}
