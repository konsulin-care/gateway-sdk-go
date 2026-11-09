package wire

// Settlement status values carried by SettlementNotification.Status (ADR-012).
const (
	// SettlementStatusPaid marks a paid settlement.
	SettlementStatusPaid = "PAID"
	// SettlementStatusExpired marks an expired payment session.
	SettlementStatusExpired = "EXPIRED"
	// SettlementStatusCanceled marks a canceled payment.
	SettlementStatusCanceled = "CANCELED"
)

// SettlementNotification is the gateway's settlement callback body.
// Status stays a string so unknown values decode without error.
type SettlementNotification struct {
	// PaymentID is the gateway payment identifier.
	PaymentID string `json:"payment_id"`
	// ExternalID is the caller-supplied external identifier.
	ExternalID string `json:"external_id"`
	// Status is the settlement status (see SettlementStatus* constants).
	Status string `json:"status"`
	// PaymentSessionID is null on the free path.
	PaymentSessionID *string `json:"payment_session_id"`
	// Amount is the amount in IDR minor units.
	Amount int64 `json:"amount"`
	// Currency is the ISO currency code.
	Currency string `json:"currency"`
	// OccurredAt is the RFC 3339 event timestamp.
	OccurredAt string `json:"occurred_at"`
	// AccessTokenURL is the URL to fetch the access token.
	AccessTokenURL string `json:"access_token_url"`
}
