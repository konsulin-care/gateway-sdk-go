package wire_test

import (
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// dtoCase binds one route DTO in wire to its Bruno example key and
// lists the JSON keys that are contract-required: a zero-valued DTO
// must still marshal every one of them (no omitempty on required
// fields, SDK-WIRE-001).
type dtoCase struct {
	name     string
	new      func() any
	required []string
}

// dtoCases is the complete route-DTO registry: every entry needs a
// byte-exact example in testdata/bruno-examples.json and carries
// exactly the required-key set below.
var dtoCases = []dtoCase{
	{name: "EnrollPartyRequest", new: func() any { return &wire.EnrollPartyRequest{} },
		required: []string{"enrollment_token", "public_key", "kid"}},
	{name: "EnrollPartyResponse", new: func() any { return &wire.EnrollPartyResponse{} },
		required: []string{"party_id", "kid"}},
	{name: "RotateKeyRequest", new: func() any { return &wire.RotateKeyRequest{} },
		required: []string{"public_key", "kid"}},
	{name: "RotateKeyResponse", new: func() any { return &wire.RotateKeyResponse{} },
		required: []string{"kid"}},
	{name: "JWK", new: func() any { return &wire.JWK{} },
		required: []string{"kty", "crv", "kid", "x", "use"}},
	{name: "JWKSResponse", new: func() any { return &wire.JWKSResponse{} },
		required: []string{"keys"}},
	{name: "PartyHealthResponse", new: func() any { return &wire.PartyHealthResponse{} },
		required: []string{"status"}},
	{name: "GatewayHealthResponse", new: func() any { return &wire.GatewayHealthResponse{} },
		required: []string{"status", "version"}},
	{name: "RegisterIdentityRequest", new: func() any { return &wire.RegisterIdentityRequest{} },
		required: []string{"resource_type", "local_resource_id", "email_hash", "phone_hash"}},
	{name: "RegisterIdentityResponse", new: func() any { return &wire.RegisterIdentityResponse{} },
		required: []string{"global_key"}},
	{name: "ResolveIdentityRequest", new: func() any { return &wire.ResolveIdentityRequest{} },
		required: []string{"email_hash", "phone_hash"}},
	{name: "ResolveIdentityResponse", new: func() any { return &wire.ResolveIdentityResponse{} },
		required: []string{"candidates"}},
	{name: "LinkIdentityRequest", new: func() any { return &wire.LinkIdentityRequest{} },
		required: []string{"global_key", "local_resource_id"}},
	{name: "LinkIdentityResponse", new: func() any { return &wire.LinkIdentityResponse{} },
		required: []string{"linked"}},
	{name: "MintApprovalRequest", new: func() any { return &wire.MintApprovalRequest{} },
		required: []string{"to", "scope", "purpose"}},
	{name: "MintApprovalResponse", new: func() any { return &wire.MintApprovalResponse{} },
		required: []string{"access_token", "jti", "expires_at"}},
	{name: "CreateListingRequest", new: func() any { return &wire.CreateListingRequest{} },
		required: []string{"name", "endpoint_url", "price"}},
	{name: "CreateListingResponse", new: func() any { return &wire.CreateListingResponse{} },
		required: []string{"listing_id", "state"}},
	{name: "ListingRow", new: func() any { return &wire.ListingRow{} },
		required: []string{"listing_id", "provider_party_id", "name", "price", "currency",
			"invocation", "price_scope", "metering"}},
	{name: "GetListingsResponse", new: func() any { return &wire.GetListingsResponse{} },
		required: []string{"listings"}},
	{name: "CreatePaymentRequest", new: func() any { return &wire.CreatePaymentRequest{} },
		required: []string{}},
	{name: "CreatePaymentResponse", new: func() any { return &wire.CreatePaymentResponse{} },
		required: []string{"payment_id", "payment_url", "amount", "currency", "expires_at",
			"payment_session_id", "status"}},
	{name: "GetPaymentResponse", new: func() any { return &wire.GetPaymentResponse{} },
		required: []string{"payment_id", "status", "amount", "currency", "payment_session_id",
			"created_at", "expires_at"}},
	{name: "AccessTokenResponse", new: func() any { return &wire.AccessTokenResponse{} },
		required: []string{"access_token", "expires_at"}},
	{name: "EnqueueWebhookRequest", new: func() any { return &wire.EnqueueWebhookRequest{} },
		required: []string{"to", "service", "payload"}},
	{name: "EnqueueWebhookResponse", new: func() any { return &wire.EnqueueWebhookResponse{} },
		required: []string{"webhook_id"}},
	{name: "SyncWebhookRequest", new: func() any { return &wire.SyncWebhookRequest{} },
		required: []string{"to", "service", "payload"}},
	{name: "SyncWebhookResponse", new: func() any { return &wire.SyncWebhookResponse{} },
		required: []string{"status_code", "body", "content_type", "webhook_id"}},
	{name: "WebhookStatusResponse", new: func() any { return &wire.WebhookStatusResponse{} },
		required: []string{"state", "attempts", "next_attempt_at", "created_at"}},
	{name: "WebhookResultRequest", new: func() any { return &wire.WebhookResultRequest{} },
		required: []string{"result"}},
	{name: "WebhookResultResponse", new: func() any { return &wire.WebhookResultResponse{} },
		required: []string{"status"}},
	{name: "ServiceReceiptBody", new: func() any { return &wire.ServiceReceiptBody{} },
		required: []string{"webhook_id", "status", "quota_remaining", "body"}},
}

// loadBrunoExamples reads the mirrored Bruno example bodies from the
// package's testdata directory (in-module path only, ADR-004).
func loadBrunoExamples(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile("testdata/bruno-examples.json")
	require.NoError(t, err)
	var examples map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &examples))
	return examples
}

// TestBrunoExamplesRoundTrip decodes every route DTO from its Bruno
// example and re-marshals it: the output must be JSON-equal to the
// example, so every required field name is byte-exact and no required
// key is missing or renamed (SDK-WIRE-001). Both directions are
// checked: an example without a DTO, or a DTO without an example,
// fails.
func TestBrunoExamplesRoundTrip(t *testing.T) {
	examples := loadBrunoExamples(t)
	byName := make(map[string]dtoCase, len(dtoCases))
	for _, tc := range dtoCases {
		byName[tc.name] = tc
	}
	require.Len(t, examples, len(dtoCases), "one Bruno example per route DTO")

	names := make([]string, 0, len(examples))
	for name := range examples {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			tc, ok := byName[name]
			require.True(t, ok, "bruno example %q matches no wire DTO", name)

			dto := tc.new()
			require.NoError(t, json.Unmarshal(examples[name], dto), "%s: decode example", name)
			out, err := json.Marshal(dto)
			require.NoError(t, err, "%s: re-marshal", name)
			assert.JSONEq(t, string(examples[name]), string(out),
				"%s: re-marshalled DTO must be JSON-equal to the Bruno example", name)
		})
	}
	for _, tc := range dtoCases {
		_, ok := examples[tc.name]
		require.True(t, ok, "missing Bruno example for %s", tc.name)
	}
}

// TestZeroValuedDTOMarshalsRequiredKeys pins the required/optional
// split: a zero-valued DTO marshals exactly its required keys — every
// required key present (no omitempty) and no optional key emitted
// (omitempty) (SDK-WIRE-001).
func TestZeroValuedDTOMarshalsRequiredKeys(t *testing.T) {
	for _, tc := range dtoCases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := json.Marshal(tc.new())
			require.NoError(t, err)
			var got map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(out, &got))

			keys := make([]string, 0, len(got))
			for k := range got {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			want := make([]string, len(tc.required))
			copy(want, tc.required)
			sort.Strings(want)
			assert.Equal(t, want, keys,
				"%s: zero-valued DTO must marshal exactly its required keys", tc.name)
		})
	}
}

// TestServiceReceiptBodyMarshalling asserts the service-receipt push
// body always carries webhook_id, status, quota_remaining and body:
// quota_remaining marshals JSON null when the provider sent no
// X-Quota-Remaining header and the verbatim provider string when it
// did (SDK-WIRE-001).
func TestServiceReceiptBodyMarshalling(t *testing.T) {
	base := wire.ServiceReceiptBody{
		WebhookID: "01HZY...",
		Status:    200,
		Body:      `{"consumed":true}`,
	}

	out, err := json.Marshal(base)
	require.NoError(t, err)
	var unset map[string]any
	require.NoError(t, json.Unmarshal(out, &unset))
	for _, key := range []string{"webhook_id", "status", "quota_remaining", "body"} {
		require.Contains(t, unset, key, "receipt body must marshal %s", key)
	}
	assert.Equal(t, "01HZY...", unset["webhook_id"])
	assert.Equal(t, float64(200), unset["status"])
	assert.Equal(t, `{"consumed":true}`, unset["body"])
	assert.Nil(t, unset["quota_remaining"], "unset quota_remaining must marshal JSON null")

	quota := "4"
	set := base
	set.QuotaRemaining = &quota
	out, err = json.Marshal(set)
	require.NoError(t, err)
	var setMap map[string]any
	require.NoError(t, json.Unmarshal(out, &setMap))
	require.Contains(t, setMap, "quota_remaining")
	assert.Equal(t, "4", setMap["quota_remaining"],
		"provider X-Quota-Remaining relayed verbatim as a string")
}

// TestListingRowEndpointURLAndMetering asserts the listings read row
// (SDK-API-001 route-shape note): endpoint_url is omitted when unset
// (invocation=webhook rows never expose the provider endpoint) and
// metering is always emitted, even on a zero-valued row.
func TestListingRowEndpointURLAndMetering(t *testing.T) {
	webhookRow := wire.ListingRow{
		ListingID:       "01HZYLISTING2",
		ProviderPartyID: "01HZXPROVIDER",
		Name:            "qc-webhook-acme-1",
		Price:           0,
		Currency:        "IDR",
		Invocation:      "webhook",
		PriceScope:      "user",
		Metering:        "provider",
	}

	out, err := json.Marshal(webhookRow)
	require.NoError(t, err)
	var row map[string]any
	require.NoError(t, json.Unmarshal(out, &row))
	assert.NotContains(t, row, "endpoint_url", "unset endpoint_url must be omitted")
	require.Contains(t, row, "metering", "metering must always be present")
	assert.Equal(t, "provider", row["metering"])

	zero, err := json.Marshal(wire.ListingRow{})
	require.NoError(t, err)
	var zeroRow map[string]any
	require.NoError(t, json.Unmarshal(zero, &zeroRow))
	assert.NotContains(t, zeroRow, "endpoint_url")
	assert.Contains(t, zeroRow, "metering", "metering is never omitempty")

	commodity := webhookRow
	commodity.Invocation = "commodity"
	commodity.EndpointURL = "https://clinician.example.com/api/research/access"
	out, err = json.Marshal(commodity)
	require.NoError(t, err)
	var commodityRow map[string]any
	require.NoError(t, json.Unmarshal(out, &commodityRow))
	assert.Contains(t, commodityRow, "endpoint_url", "set endpoint_url must be emitted")
}

// TestDecodeResponseWithUnknownFields asserts forward compatibility:
// a response carrying fields the SDK does not know decodes without
// error and every known field keeps its value (SDK-WIRE-001).
func TestDecodeResponseWithUnknownFields(t *testing.T) {
	payload := `{
		"payment_id": "01HZY...",
		"status": "PAID",
		"amount": 53200,
		"currency": "IDR",
		"payment_session_id": "ps-661f87c614802d6c402cd82d",
		"created_at": "2026-12-31T23:58:00Z",
		"expires_at": "2026-12-31T23:59:59Z",
		"customer_ref": "qc-user-hash-operator",
		"future_field": {"nested": [1, 2]},
		"x_unknown": "added-by-a-newer-gateway"
	}`
	var payment wire.GetPaymentResponse
	require.NoError(t, json.Unmarshal([]byte(payload), &payment))
	assert.Equal(t, "01HZY...", payment.PaymentID)
	assert.Equal(t, "PAID", payment.Status)
	assert.Equal(t, int64(53200), payment.Amount)
	assert.Equal(t, "IDR", payment.Currency)
	require.NotNil(t, payment.PaymentSessionID)
	assert.Equal(t, "ps-661f87c614802d6c402cd82d", *payment.PaymentSessionID)
	assert.Equal(t, "2026-12-31T23:58:00Z", payment.CreatedAt)
	require.NotNil(t, payment.ExpiresAt)
	assert.Equal(t, "2026-12-31T23:59:59Z", *payment.ExpiresAt)
	assert.Equal(t, "qc-user-hash-operator", payment.CustomerRef)

	statusPayload := `{
		"state": "failed",
		"attempts": 4,
		"next_attempt_at": "2026-12-31T12:05:00Z",
		"last_error": "payment_required",
		"created_at": "2026-12-31T11:59:59Z",
		"state_v2": "terminal"
	}`
	var status wire.WebhookStatusResponse
	require.NoError(t, json.Unmarshal([]byte(statusPayload), &status))
	assert.Equal(t, "failed", status.State)
	assert.Equal(t, 4, status.Attempts)
	assert.Equal(t, "2026-12-31T12:05:00Z", status.NextAttemptAt)
	assert.Equal(t, "payment_required", status.LastError)
	assert.Equal(t, "2026-12-31T11:59:59Z", status.CreatedAt)
}
