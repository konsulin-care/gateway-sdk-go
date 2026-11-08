package listings

import (
	"context"
	"fmt"
	"net/url"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// ListOption narrows GET /v1/listings (SDKP-007, GWP-005): each option
// sets one query parameter — name, provider_party_id, or invocation —
// on the public read. An option with an empty value sets no parameter,
// so an unset filter never sends an empty match.
type ListOption func(q url.Values)

// WithName filters the read to listings whose name equals name (query
// parameter name, GWP-005).
// Parameters: name — the listing title to match; empty sets no
// parameter.
// Returns: the ListOption for Client.List.
func WithName(name string) ListOption {
	return func(q url.Values) {
		if name != "" {
			q.Set("name", name)
		}
	}
}

// WithProviderPartyID filters the read to listings provided by
// providerPartyID (query parameter provider_party_id, GWP-005).
// Parameters: providerPartyID — the providing party id; empty sets no
// parameter.
// Returns: the ListOption for Client.List.
func WithProviderPartyID(providerPartyID string) ListOption {
	return func(q url.Values) {
		if providerPartyID != "" {
			q.Set("provider_party_id", providerPartyID)
		}
	}
}

// WithInvocation filters the read to listings with the given
// invocation kind (query parameter invocation — "webhook" or
// "commodity" — GWP-005).
// Parameters: invocation — the invocation kind to match; empty sets no
// parameter.
// Returns: the ListOption for Client.List.
func WithInvocation(invocation string) ListOption {
	return func(q url.Values) {
		if invocation != "" {
			q.Set("invocation", invocation)
		}
	}
}

// FindByName resolves the single active listing named name provided by
// providerPartyID (SDKP-007): List runs with both filters and exactly
// one row must match — zero or multiple matches fail closed.
// Parameters: ctx is the call context; providerPartyID is the providing
// party; name is the listing title.
// Returns: the single matching *wire.ListingRow, or an error when the
// read fails or the match count is not one. Never panics.
func (c *Client) FindByName(ctx context.Context, providerPartyID, name string) (*wire.ListingRow, error) {
	resp, err := c.List(ctx, WithProviderPartyID(providerPartyID), WithName(name))
	if err != nil {
		return nil, err
	}
	switch matches := resp.Listings; len(matches) {
	case 1:
		return &matches[0], nil
	case 0:
		return nil, fmt.Errorf("listings: find by name: no listing named %q for provider %q",
			name, providerPartyID)
	default:
		return nil, fmt.Errorf("listings: find by name: %d listings named %q for provider %q",
			len(matches), name, providerPartyID)
	}
}
