package wire_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

const paidExample = `{"payment_id":"pay_1","external_id":"ext_1","status":"PAID",` +
	`"payment_session_id":"ps_1","amount":150000,"currency":"IDR",` +
	`"occurred_at":"2025-01-01T00:00:00Z","access_token_url":"https://gw/x/token"}`

func TestSettlementPaidRoundTrip(t *testing.T) {
	var n wire.SettlementNotification
	require.NoError(t, json.Unmarshal([]byte(paidExample), &n))
	assert.Equal(t, "pay_1", n.PaymentID)
	assert.Equal(t, "ext_1", n.ExternalID)
	assert.Equal(t, wire.SettlementStatusPaid, n.Status)
	require.NotNil(t, n.PaymentSessionID)
	assert.Equal(t, "ps_1", *n.PaymentSessionID)
	assert.Equal(t, int64(150000), n.Amount)
	assert.Equal(t, "IDR", n.Currency)
	assert.Equal(t, "2025-01-01T00:00:00Z", n.OccurredAt)
	assert.Equal(t, "https://gw/x/token", n.AccessTokenURL)
	out, err := json.Marshal(n)
	require.NoError(t, err)
	assert.JSONEq(t, paidExample, string(out))
}

func TestSettlementFreePathNullSession(t *testing.T) {
	body := `{"payment_id":"p","external_id":"e","status":"PAID","payment_session_id":null,` +
		`"amount":0,"currency":"IDR","occurred_at":"t","access_token_url":"u"}`
	var n wire.SettlementNotification
	require.NoError(t, json.Unmarshal([]byte(body), &n))
	assert.Nil(t, n.PaymentSessionID)
}

func TestSettlementUnknownStatusAndConstants(t *testing.T) {
	var n wire.SettlementNotification
	require.NoError(t, json.Unmarshal([]byte(`{"status":"REFUNDED"}`), &n))
	assert.Equal(t, "REFUNDED", n.Status)
	assert.Equal(t, "PAID", wire.SettlementStatusPaid)
	assert.Equal(t, "EXPIRED", wire.SettlementStatusExpired)
	assert.Equal(t, "CANCELED", wire.SettlementStatusCanceled)
}
