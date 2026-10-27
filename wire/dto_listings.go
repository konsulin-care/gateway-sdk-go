package wire

// CreateListingRequest is the POST /v1/listings body enlisting a
// service or commodity in the marketplace.
type CreateListingRequest struct {
	// Name is the listing title shown to buyers.
	Name string `json:"name"`
	// Description is the optional marketplace detail.
	Description string `json:"description,omitempty"`
	// EndpointURL is where the buyer reaches the provider after
	// authorization.
	EndpointURL string `json:"endpoint_url"`
	// Price is the integer amount in IDR minor units; 0 marks a free
	// listing.
	Price int64 `json:"price"`
	// Invocation is optional: "webhook" or "commodity" (default).
	Invocation string `json:"invocation,omitempty"`
	// PriceScope is optional: "party" or "user" (default).
	PriceScope string `json:"price_scope,omitempty"`
	// Metering is optional: "gateway" (default) or "provider".
	Metering string `json:"metering,omitempty"`
}

// CreateListingResponse is the 200 body of POST /v1/listings.
type CreateListingResponse struct {
	// ListingID is the id buyers reference at payment creation.
	ListingID string `json:"listing_id"`
	// State is the stored listing state ("active").
	State string `json:"state"`
}

// ListingRow is one row of GET /v1/listings. endpoint_url is omitted
// for invocation=webhook rows (the public read never exposes the
// provider's webhook endpoint); metering is always present.
type ListingRow struct {
	// ListingID is the listing's id.
	ListingID string `json:"listing_id"`
	// ProviderPartyID is the providing party.
	ProviderPartyID string `json:"provider_party_id"`
	// Name is the listing title.
	Name string `json:"name"`
	// Description is the detail for the marketplace read; omitted
	// when unset.
	Description string `json:"description,omitempty"`
	// EndpointURL is present for commodity listings and omitted for
	// invocation=webhook rows.
	EndpointURL string `json:"endpoint_url,omitempty"`
	// Price is the amount in IDR minor units.
	Price int64 `json:"price"`
	// Currency is the market currency ("IDR").
	Currency string `json:"currency"`
	// Invocation is "webhook" or "commodity".
	Invocation string `json:"invocation"`
	// PriceScope is "party" or "user".
	PriceScope string `json:"price_scope"`
	// Metering is "gateway" or "provider"; always emitted (legacy
	// rows read back as "gateway").
	Metering string `json:"metering"`
	// ProviderTier is the operator trust tier; omitted when unset.
	ProviderTier string `json:"provider_tier,omitempty"`
	// ProviderOrgName is the provider display name; omitted when
	// unset (absent whenever provider_tier is absent).
	ProviderOrgName string `json:"provider_org_name,omitempty"`
}

// GetListingsResponse is the 200 body of GET /v1/listings: active
// listings only.
type GetListingsResponse struct {
	// Listings are the active marketplace rows.
	Listings []ListingRow `json:"listings"`
}
