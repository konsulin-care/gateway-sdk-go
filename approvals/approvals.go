package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// Client routes the approval ticket endpoints (SDK-API-001,
// SDK-API-002): Mint executes through the injected *client.Client with
// the route's party auth class — every call is signed by the client's
// party signer (AuthParty).
type Client struct {
	cli *client.Client
}

// New binds the approval routes to a configured client.
// Parameters: cli is the configured client used by Mint (must be
// non-nil).
// Returns: the routes Client, or an error on a nil client. Never panics.
func New(cli *client.Client) (*Client, error) {
	if cli == nil {
		return nil, errors.New("approvals: nil client")
	}
	return &Client{cli: cli}, nil
}

// Mint mints an approval/STS ticket for a recipient party at POST
// /v1/approvals (SDK-API-001): the request is signed by the client's
// party signer (AuthParty), carries an Idempotency-Key (an idempotent
// create, SDK-CLIENT-002), and the 200 body decodes into the minted
// ticket. A missing capability grant surfaces as a 403 *wire.Error
// (capability_denied) after one attempt — never retried around.
// Parameters: ctx is the call context; req is the mint request naming
// the recipient party, the allowlisted scope ("referral" or
// "export:<study>"), the literal purpose, and the requested TTL.
// Returns: the decoded MintApprovalResponse, or an error — a gateway
// failure surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) Mint(ctx context.Context, req wire.MintApprovalRequest) (*wire.MintApprovalResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("approvals: mint: request JSON: %w", err)
	}
	resp, err := c.cli.Do(ctx, client.Request{
		Method:     http.MethodPost,
		Path:       "/v1/approvals",
		Body:       body,
		Auth:       wire.AuthParty,
		Idempotent: true,
	})
	if err != nil {
		return nil, err
	}
	var out wire.MintApprovalResponse
	if err := client.DecodeInto(resp, &out); err != nil {
		return nil, fmt.Errorf("approvals: mint: %w", err)
	}
	return &out, nil
}
