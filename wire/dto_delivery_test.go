package wire_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

func TestDeliveryBodyRoundTrip(t *testing.T) {
	in := `{"envelope":"a.b.c.d.e","result_ticket":"tkt-1"}`
	var b wire.DeliveryBody
	require.NoError(t, json.Unmarshal([]byte(in), &b))
	assert.Equal(t, "a.b.c.d.e", b.Envelope)
	assert.Equal(t, "tkt-1", b.ResultTicket)
	out, err := json.Marshal(b)
	require.NoError(t, err)
	assert.JSONEq(t, in, string(out))
}

func TestContentTypeJOSE(t *testing.T) {
	assert.Equal(t, "application/jose", wire.ContentTypeJOSE)
}
