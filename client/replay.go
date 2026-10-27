package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/konsulin-care/gateway-sdk-go/auth"
)

// scopeJTI is the replay-cache key space of outbound attempt jtis. The
// client package does not import verify, so the scope string matches
// verify.ScopeJTI by value and keeps one cache shared across both
// directions.
const scopeJTI = "jti"

// signAttempt produces this attempt's Authorization token (SDK-RETRY-001,
// ADR-008): one fresh ks-party+jwt per attempt, so a retry of one logical
// request never carries a previous attempt's jti. Without an injected
// ReplayCache the fresh jti comes from auth.SignPartyAttempt; with one
// (WithReplayCache) the jti is minted here and reserved in scope "jti"
// until the token's expiry before signing. A reservation error or a
// duplicate verdict fails the attempt before any network I/O (fail
// closed) — it is a known client-side failure, never an
// ErrOutcomeUnknown exhaustion.
// Parameters: ctx — the call context, carried into the reservation.
// Returns: the compact token, or an error.
func (c *Client) signAttempt(ctx context.Context) (string, error) {
	if c.replay == nil {
		return c.signPartyRequest()
	}
	jti, err := auth.NewJti()
	if err != nil {
		return "", fmt.Errorf("client: fresh attempt jti: %w", err)
	}
	until := c.now().Add(time.Duration(auth.MaxPartyLifetime) * time.Second)
	fresh, err := c.replay.Check(ctx, scopeJTI, jti, until)
	if err != nil {
		return "", fmt.Errorf("client: reserve attempt jti: %w", err)
	}
	if !fresh {
		return "", errors.New("client: reserve attempt jti: duplicate")
	}
	iat := c.now().Unix()
	claims := auth.PartyClaims{
		Aud: gatewayAudience,
		Exp: iat + auth.MaxPartyLifetime,
		Iat: iat,
		Iss: c.partyID,
		Jti: jti,
	}
	tok, err := auth.SignPartyRequest(c.signer, claims)
	if err != nil {
		return "", fmt.Errorf("client: sign party request: %w", err)
	}
	return tok, nil
}
