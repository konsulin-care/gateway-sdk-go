package payments

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/gatewaytest"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// testPartyID is the fixture party id (the signer's iss and the canned
// gatewaytest rows' party id) in every fixture below.
const testPartyID = "01HZYPARTY0000000000"

// paymentID is the canned gatewaytest payment id every route example
// below references.
const paymentID = "01HZYPAYMENT000001"

// freePathCreateBody is the free-path POST /v1/payments 200 example:
// payment_url, expires_at, and payment_session_id are explicit JSON
// nulls and the status is PAID.
const freePathCreateBody = `{"payment_id":"01HZYPAYMENT000002","payment_url":null,"amount":0,` +
	`"currency":"IDR","expires_at":null,"payment_session_id":null,"status":"PAID"}`

// freePathGetBody is the matching free-path GET /v1/payments/{id} 200
// example: payment_session_id and expires_at are explicit nulls.
const freePathGetBody = `{"payment_id":"01HZYPAYMENT000002","status":"PAID","amount":0,` +
	`"currency":"IDR","payment_session_id":null,"created_at":"2026-12-31T23:58:01Z","expires_at":null}`

// fixture wires a fake gateway, a client signed by an Ed25519 key, and a
// payments.Client bound to it; extra client options are appended last so
// a test can override the retry policy.
func fixture(t *testing.T, opts ...client.Option) (*gatewaytest.Gateway, *Client, ed25519.PrivateKey) {
	t.Helper()
	g := gatewaytest.NewGateway()
	t.Cleanup(g.Close)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	base := []client.Option{
		client.WithBaseURL(g.URL()),
		client.WithInsecureTransport(),
		client.WithSigner(testPartyID, priv),
	}
	cli, err := client.New(append(base, opts...)...)
	require.NoError(t, err)
	pay, err := New(cli)
	require.NoError(t, err)
	return g, pay, priv
}

// assertSignedByClientPartyToken asserts one recorded request carries a
// Bearer party token signed by the fixture client's signer.
func assertSignedByClientPartyToken(t *testing.T, rec gatewaytest.RecordedRequest, priv ed25519.PrivateKey) {
	t.Helper()
	require.True(t, strings.HasPrefix(rec.Authorization, "Bearer "), "route must carry a party token")
	pub := priv.Public().(ed25519.PublicKey)
	_, _, err := jws.VerifyEd25519(pub, []byte(strings.TrimPrefix(rec.Authorization, "Bearer ")))
	require.NoError(t, err, "route must be signed by the client signer")
}

// TestNewRejectsNilClient covers the constructor guard: a nil client
// fails New instead of deferring a nil panic to the first call.
func TestNewRejectsNilClient(t *testing.T) {
	pay, err := New(nil)
	require.Error(t, err)
	assert.Nil(t, pay)
}

// TestCreatePostsWithPartyAuthAndIdempotencyKey covers assertion 1:
// Create POSTs /v1/payments with party auth and an Idempotency-Key and
// decodes the canned priced-path example body.
func TestCreatePostsWithPartyAuthAndIdempotencyKey(t *testing.T) {
	g, pay, priv := fixture(t)
	resp, err := pay.Create(context.Background(), wire.CreatePaymentRequest{
		ListingID: "01HZYLISTING000001", CustomerRef: "sha256:c2FsdC1oYXNo",
	})
	require.NoError(t, err)
	assert.Equal(t, paymentID, resp.PaymentID, "create must decode the response DTO")
	require.NotNil(t, resp.PaymentURL, "the priced path carries a checkout link")
	assert.Equal(t, "https://checkout.example/pay-01hzypayment000001", *resp.PaymentURL)
	assert.Equal(t, int64(53200), resp.Amount)
	assert.Equal(t, "IDR", resp.Currency)
	require.NotNil(t, resp.ExpiresAt)
	require.NotNil(t, resp.PaymentSessionID)
	assert.Equal(t, "ps-661f87c614802d6c402cd82d", *resp.PaymentSessionID)
	assert.Equal(t, "PENDING", resp.Status)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/v1/payments", rec.Path)
	require.NotEmpty(t, rec.IdempotencyKey, "create is an idempotent create (SDK-CLIENT-002)")
	assertSignedByClientPartyToken(t, rec, priv)
	var body wire.CreatePaymentRequest
	require.NoError(t, json.Unmarshal(rec.Body, &body))
	assert.Equal(t, "01HZYLISTING000001", body.ListingID)
	assert.Equal(t, "sha256:c2FsdC1oYXNo", body.CustomerRef)
}

// TestCreateDecodesFreePathNulls covers assertion 4 for Create: the
// free-path example body — explicit nulls and status PAID — decodes
// with nil pointer fields.
func TestCreateDecodesFreePathNulls(t *testing.T) {
	g, pay, _ := fixture(t)
	g.Script(http.MethodPost, "/v1/payments", gatewaytest.ScriptStep{
		Status: http.StatusOK,
		Body:   []byte(freePathCreateBody),
	})
	resp, err := pay.Create(context.Background(), wire.CreatePaymentRequest{
		Domain: "clinic.example", Opaque: "order-7", Amount: 0,
	})
	require.NoError(t, err)
	assert.Equal(t, "01HZYPAYMENT000002", resp.PaymentID)
	assert.Nil(t, resp.PaymentURL, "the free path sends an explicit null")
	assert.Nil(t, resp.ExpiresAt, "the free path sends an explicit null")
	assert.Nil(t, resp.PaymentSessionID, "the free path sends an explicit null")
	assert.Equal(t, "PAID", resp.Status)
}

// TestGetGetsWithPartyAuthAndNoIdempotencyKey covers assertion 2: Get
// GETs /v1/payments/{id} with party auth and no Idempotency-Key (a
// read, not a create) and decodes the canned example body.
func TestGetGetsWithPartyAuthAndNoIdempotencyKey(t *testing.T) {
	g, pay, priv := fixture(t)
	resp, err := pay.Get(context.Background(), paymentID)
	require.NoError(t, err)
	assert.Equal(t, paymentID, resp.PaymentID, "get must decode the response DTO")
	assert.Equal(t, "PAID", resp.Status)
	assert.Equal(t, int64(53200), resp.Amount)
	assert.Equal(t, "IDR", resp.Currency)
	require.NotNil(t, resp.PaymentSessionID)
	assert.Equal(t, "ps-661f87c614802d6c402cd82d", *resp.PaymentSessionID)
	assert.Equal(t, "2026-12-31T23:58:00Z", resp.CreatedAt)
	assert.Nil(t, resp.ExpiresAt, "the canned read carries no expiry")

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodGet, rec.Method)
	assert.Equal(t, "/v1/payments/"+paymentID, rec.Path)
	assertSignedByClientPartyToken(t, rec, priv)
	assert.Empty(t, rec.IdempotencyKey, "the reconciliation read must not send an Idempotency-Key")
}

// TestGetDecodesFreePathNulls covers assertion 4 for Get: the free-path
// example body — explicit nulls — decodes with nil pointer fields.
func TestGetDecodesFreePathNulls(t *testing.T) {
	g, pay, _ := fixture(t)
	g.Script(http.MethodGet, "/v1/payments/{id}", gatewaytest.ScriptStep{
		Status: http.StatusOK,
		Body:   []byte(freePathGetBody),
	})
	resp, err := pay.Get(context.Background(), "01HZYPAYMENT000002")
	require.NoError(t, err)
	assert.Equal(t, "01HZYPAYMENT000002", resp.PaymentID)
	assert.Equal(t, "PAID", resp.Status)
	assert.Nil(t, resp.PaymentSessionID, "the free path sends an explicit null")
	assert.Nil(t, resp.ExpiresAt, "the free path sends an explicit null")
}

// TestAccessTokenPostsWithPartyAuthAndIdempotencyKey covers assertion
// 3: AccessToken POSTs /v1/payments/{id}/access-token with party auth
// and an Idempotency-Key, sends no request body, and decodes the canned
// example body.
func TestAccessTokenPostsWithPartyAuthAndIdempotencyKey(t *testing.T) {
	g, pay, priv := fixture(t)
	resp, err := pay.AccessToken(context.Background(), paymentID)
	require.NoError(t, err)
	assert.Equal(t, "eyJhbGciOiJFZERTQSIsImtpZCI6Imd3LWtleS0xIn0.cGF5bG9hZA.c2ln",
		resp.AccessToken, "access-token must decode the response DTO")
	assert.Equal(t, "2026-12-31T12:14:00Z", resp.ExpiresAt)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/v1/payments/"+paymentID+"/access-token", rec.Path)
	require.NotEmpty(t, rec.IdempotencyKey, "the access-token mint is an idempotent create (SDK-CLIENT-002)")
	assertSignedByClientPartyToken(t, rec, priv)
	assert.Empty(t, rec.Body, "the mint carries no request body")
}
