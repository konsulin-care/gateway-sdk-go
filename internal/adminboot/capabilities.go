package adminboot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/konsulin-care/gateway-sdk-go/wire"
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

// revokeCapabilityResponse is the Bruno success shape of
// DELETE /v1/admin/parties/{id}/capabilities/{capability}: the
// revoked capability with its direction and revoked status.
type revokeCapabilityResponse struct {
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

// RevokeCapability revokes capability from partyID at
// DELETE /v1/admin/parties/{id}/capabilities/{capability} with the
// admin bearer. A non-2xx response surfaces as *wire.Error; the admin
// bearer is never logged.
//
// Parameters: ctx is the call context; bearer is the admin token from
// Login; partyID is the party to revoke the capability from;
// capability is the capability id to revoke (e.g.
// wire.CapabilityWebhookInvoke).
// Returns: nil on 2xx, or the failure.
func (c *Client) RevokeCapability(ctx context.Context, bearer, partyID, capability string) error {
	if partyID == "" {
		return fmt.Errorf("adminboot: revoke capability: party id must not be empty")
	}
	if capability == "" {
		return fmt.Errorf("adminboot: revoke capability: capability must not be empty")
	}
	var resp revokeCapabilityResponse
	path := "/v1/admin/parties/" + url.PathEscape(partyID) + "/capabilities/" + url.PathEscape(capability)
	return c.del(ctx, path, bearer, &resp)
}

// del issues one admin DELETE through the client: bearer is sent as
// "Authorization: Bearer" when non-empty, and a 2xx response decodes
// into out (nil skips the decode). Any non-2xx response returns the
// wire error envelope as *wire.Error (SDK-WIRE-003). The request is
// never echoed into errors or logs.
//
// Parameters: ctx is the call context; path is the request path off
// the base URL; bearer is the admin token; out receives the decoded
// 2xx body when non-nil.
// Returns: nil on 2xx, or the failure (a gateway error as *wire.Error).
func (c *Client) del(ctx context.Context, path, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.base+path, nil)
	if err != nil {
		return fmt.Errorf("adminboot: build request %s: %w", path, err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("adminboot: %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("adminboot: read %s response: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return wire.DecodeError(resp.StatusCode, body)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("adminboot: decode %s response: %w", path, err)
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
