package listings

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

// mixedRowsBody is one scripted GET /v1/listings body with a webhook row
// (endpoint_url omitted) and a commodity row (endpoint_url present), so
// the endpoint_url-omission and metering decode rules face both shapes.
const mixedRowsBody = `{"listings":[` +
	`{"listing_id":"01HZYLISTINGWEBHOOK01","provider_party_id":"01HZXPROVIDER000001",` +
	`"name":"Webhook callback feed","price":1000,"currency":"IDR","invocation":"webhook",` +
	`"price_scope":"party","metering":"gateway"},` +
	`{"listing_id":"01HZYLISTING000002","provider_party_id":"01HZXPROVIDER000002",` +
	`"name":"Commodity extract","endpoint_url":"https://provider.example.com/api/access",` +
	`"price":2000,"currency":"IDR","invocation":"commodity","price_scope":"user",` +
	`"metering":"provider"}]}`

// fixture wires a fake gateway, a client signed by an Ed25519 key, and a
// listings.Client bound to it; extra client options are appended last so
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
	ls, err := New(cli)
	require.NoError(t, err)
	return g, ls, priv
}

// TestNewRejectsNilClient covers the constructor guard: a nil client
// fails New instead of deferring a nil panic to the first call.
func TestNewRejectsNilClient(t *testing.T) {
	ls, err := New(nil)
	require.Error(t, err)
	assert.Nil(t, ls)
}

// TestCreatePostsWithPartyAuthAndIdempotencyKey covers assertion 1:
// Create POSTs /v1/listings with party auth and an Idempotency-Key and
// decodes the canned response DTO.
func TestCreatePostsWithPartyAuthAndIdempotencyKey(t *testing.T) {
	g, ls, priv := fixture(t)
	resp, err := ls.Create(context.Background(), wire.CreateListingRequest{
		Name:        "Curated pseudonymized research data",
		EndpointURL: "https://clinician.example.com/api/research/access",
		Price:       53200, Invocation: "commodity", Metering: "gateway",
	})
	require.NoError(t, err)
	assert.Equal(t, "01HZYLISTING000001", resp.ListingID, "create must decode the response DTO")
	assert.Equal(t, "active", resp.State)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/v1/listings", rec.Path)
	require.NotEmpty(t, rec.IdempotencyKey, "create is an idempotent create (SDK-CLIENT-002)")
	require.True(t, strings.HasPrefix(rec.Authorization, "Bearer "), "create must carry a party token")
	pub := priv.Public().(ed25519.PublicKey)
	_, _, err = jws.VerifyEd25519(pub, []byte(strings.TrimPrefix(rec.Authorization, "Bearer ")))
	require.NoError(t, err, "create must be signed by the client signer")
	var body wire.CreateListingRequest
	require.NoError(t, json.Unmarshal(rec.Body, &body))
	assert.Equal(t, "Curated pseudonymized research data", body.Name)
	assert.Equal(t, int64(53200), body.Price)
}

// TestListGetsWithoutAuthorization covers assertion 2: List GETs
// /v1/listings with the route's public auth class — no Authorization
// header and no Idempotency-Key (a read, not a create).
func TestListGetsWithoutAuthorization(t *testing.T) {
	g, ls, _ := fixture(t)
	resp, err := ls.List(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, resp.Listings, "list must decode the canned marketplace rows")

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodGet, rec.Method)
	assert.Equal(t, "/v1/listings", rec.Path)
	assert.Empty(t, rec.Authorization, "the public read must send no Authorization header")
	assert.Empty(t, rec.IdempotencyKey, "list must not send an Idempotency-Key")
}

// TestListDecodesMeteringOnEveryRow covers assertion 3: metering decodes
// on every row — gateway-metered and provider-metered rows alike.
func TestListDecodesMeteringOnEveryRow(t *testing.T) {
	g, ls, _ := fixture(t)
	g.Script(http.MethodGet, "/v1/listings", gatewaytest.ScriptStep{
		Status: http.StatusOK,
		Body:   []byte(mixedRowsBody),
	})
	resp, err := ls.List(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Listings, 2, "both scripted rows must decode")
	assert.Equal(t, "gateway", resp.Listings[0].Metering, "metering must decode on every row")
	assert.Equal(t, "provider", resp.Listings[1].Metering, "metering must decode on every row")
}

// TestListOmitsEndpointURLForWebhookRows covers assertion 4: a webhook
// row (invocation=webhook) decodes with no endpoint_url — the public
// read never exposes a provider endpoint — while a commodity row keeps
// its set endpoint_url.
func TestListOmitsEndpointURLForWebhookRows(t *testing.T) {
	g, ls, _ := fixture(t)
	g.Script(http.MethodGet, "/v1/listings", gatewaytest.ScriptStep{
		Status: http.StatusOK,
		Body:   []byte(mixedRowsBody),
	})
	resp, err := ls.List(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Listings, 2, "both scripted rows must decode")
	webhookRow, commodityRow := resp.Listings[0], resp.Listings[1]
	assert.Equal(t, "webhook", webhookRow.Invocation)
	assert.Empty(t, webhookRow.EndpointURL, "endpoint_url must be absent for invocation=webhook rows")
	assert.Equal(t, "commodity", commodityRow.Invocation)
	assert.Equal(t, "https://provider.example.com/api/access", commodityRow.EndpointURL,
		"commodity rows keep their endpoint_url")
}
