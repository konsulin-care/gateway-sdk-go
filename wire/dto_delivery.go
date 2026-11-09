package wire

// ContentTypeJOSE is the Content-Type of a synchronous webhook reply carrying
// a compact JWE envelope.
const ContentTypeJOSE = "application/jose"

// DeliveryBody is the JSON body the gateway POSTs to a webhook endpoint on
// invocation. The asynchronous result is posted back using the existing
// WebhookResultRequest body.
type DeliveryBody struct {
	// Envelope is the compact JWE carrying the request payload.
	Envelope string `json:"envelope"`
	// ResultTicket is the single-use ticket authorizing the async result post.
	ResultTicket string `json:"result_ticket"`
}
