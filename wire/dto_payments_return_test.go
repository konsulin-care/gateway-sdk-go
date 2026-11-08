package wire

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreatePaymentRequestReturnURLsMarshal(t *testing.T) {
	b, err := json.Marshal(CreatePaymentRequest{
		ListingID:        "lst_1",
		SuccessReturnURL: "https://a.example/ok",
		CancelReturnURL:  "https://a.example/cancel",
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"listing_id":"lst_1","success_return_url":"https://a.example/ok","cancel_return_url":"https://a.example/cancel"}`, string(b))
}

func TestCreatePaymentRequestReturnURLsOmitted(t *testing.T) {
	b, err := json.Marshal(CreatePaymentRequest{ListingID: "lst_1"})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "success_return_url")
	assert.NotContains(t, string(b), "cancel_return_url")
}

func TestCreatePaymentRequestBrunoExampleRoundTrip(t *testing.T) {
	body := `{"listing_id":"lst_01","customer_ref":"cref_hash","success_return_url":"https://app.example.com/pay/success","cancel_return_url":"https://app.example.com/pay/cancel"}`
	var req CreatePaymentRequest
	require.NoError(t, json.Unmarshal([]byte(body), &req))
	out, err := json.Marshal(req)
	require.NoError(t, err)
	assert.JSONEq(t, body, string(out))
}
