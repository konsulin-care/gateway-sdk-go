package wire

// CreatePaymentRequest is the POST /v1/payments body: exactly one of
// listing mode (listing_id, amount read from the listing row) or
// seller-amount mode (domain + opaque + amount >= 1); neither mode is
// a 400 (GW-PAY-006).
type CreatePaymentRequest struct {
	// ListingID is the active listing to purchase in listing mode.
	// Empty in seller-amount mode (the gateway treats "" as absent).
	ListingID string `json:"listing_id,omitempty"`
	// CustomerRef is the end-user peppered hash; required for
	// price_scope=user listings, never plaintext PII.
	CustomerRef string `json:"customer_ref,omitempty"`
	// Domain is the seller-mode domain (no ":", never "listing").
	Domain string `json:"domain,omitempty"`
	// Opaque is the seller-mode opaque identifier.
	Opaque string `json:"opaque,omitempty"`
	// Amount is the seller-mode amount (>= 1); listing mode reads
	// the price from the listing row instead.
	Amount int64 `json:"amount,omitempty"`
}

// CreatePaymentResponse is the 200 body of POST /v1/payments. The
// nullable fields are explicit JSON nulls on the free path
// (payment_url/expires_at/payment_session_id null, status PAID) and
// carry values on the priced path (status PENDING).
type CreatePaymentResponse struct {
	// PaymentID is the created payment's id.
	PaymentID string `json:"payment_id"`
	// PaymentURL is the provider checkout link; null on the free path.
	PaymentURL *string `json:"payment_url"`
	// Amount is the charged amount in IDR minor units.
	Amount int64 `json:"amount"`
	// Currency is the market currency ("IDR").
	Currency string `json:"currency"`
	// ExpiresAt is the session expiry (RFC 3339); null on the free path.
	ExpiresAt *string `json:"expires_at"`
	// PaymentSessionID is the provider session id; null on the free path.
	PaymentSessionID *string `json:"payment_session_id"`
	// Status is "PENDING", "PAID", "EXPIRED" or "CANCELED".
	Status string `json:"status"`
}

// GetPaymentResponse is the 200 body of GET /v1/payments/{id}, the
// buyer-owned reconciliation read.
type GetPaymentResponse struct {
	// PaymentID is the payment's id.
	PaymentID string `json:"payment_id"`
	// Status is the gateway status vocabulary value.
	Status string `json:"status"`
	// Amount is the amount in IDR minor units.
	Amount int64 `json:"amount"`
	// Currency is the market currency ("IDR").
	Currency string `json:"currency"`
	// PaymentSessionID is the provider session id; null when the
	// payment settled without a session.
	PaymentSessionID *string `json:"payment_session_id"`
	// CustomerRef surfaces the stored entitlement hash when present.
	CustomerRef string `json:"customer_ref,omitempty"`
	// CreatedAt is the row creation time (RFC 3339).
	CreatedAt string `json:"created_at"`
	// ExpiresAt is the expiry (RFC 3339); null on the free path.
	ExpiresAt *string `json:"expires_at"`
}

// AccessTokenResponse is the 200 body of
// POST /v1/payments/{id}/access-token: the direct-channel ticket.
type AccessTokenResponse struct {
	// AccessToken is the minted ks-access+jwt ticket.
	AccessToken string `json:"access_token"`
	// ExpiresAt is the ticket expiry (RFC 3339, <= 900 s lifetime).
	ExpiresAt string `json:"expires_at"`
}
