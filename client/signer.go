package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/konsulin-care/gateway-sdk-go/auth"
)

// gatewayAudience is the only aud of an outbound ks-party+jwt (aud = gateway).
const gatewayAudience = "gateway"

// ErrNoSigner fails a party-auth request without WithSigner, before network I/O.
var ErrNoSigner = errors.New("client: party-authenticated request requires WithSigner")

// signPartyRequest signs one fresh ks-party+jwt per attempt (SDK-AUTH-003).
// Returns: the compact token, or an error from claims validation or signing.
func (c *Client) signPartyRequest() (string, error) {
	iat := time.Now().Unix()
	claims := auth.PartyClaims{Aud: gatewayAudience, Exp: iat + auth.MaxPartyLifetime, Iat: iat, Iss: c.partyID}
	tok, err := auth.SignPartyAttempt(c.signer, claims)
	if err != nil {
		return "", fmt.Errorf("client: sign party request: %w", err)
	}
	return tok, nil
}
