package webhooks

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// webhookID is the canned gatewaytest outbox row id every route
// example below references.
const webhookID = "01JAV3Q6R7K9X2M4N8P0Q1S5T7"

// hook006Body is the scripted 402 GW-HOOK-006 error envelope (stop
// disposition, SDK-RETRY-003).
const hook006Body = `{"error":{"code":"GW-HOOK-006","message":"payment required","request_id":"req-hook-006"}}`

// hook007Body is the scripted 401 GW-HOOK-007 error envelope (reauth
// disposition, terminal).
const hook007Body = `{"error":{"code":"GW-HOOK-007","message":"result ticket rejected","request_id":"req-hook-007"}}`

// hook009Body is the scripted 503 GW-HOOK-009 error envelope (retry
// disposition, SDK-RETRY-002).
const hook009Body = `{"error":{"code":"GW-HOOK-009","message":"upstream busy","request_id":"req-hook-009"}}`

// retryingPolicy is a multi-attempt client retry policy: tests that
// assert "exactly one attempt" or "returns after one attempt" pass it
// so a violation would actually retry and be observable.
var retryingPolicy = client.WithRetry(client.RetryPolicy{
	MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
})

// fixture wires a fake gateway, a client signed by an Ed25519 key, and
// a webhooks.Client bound to it; extra client options are appended last
// so a test can override the retry policy.
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
	wh, err := New(cli, g.URL())
	require.NoError(t, err)
	return g, wh, priv
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

// TestEnqueuePostsWithPartyAuthAndIdempotencyKey covers assertion 1:
// Enqueue POSTs /v1/webhooks with party auth and an Idempotency-Key and
// decodes the canned 202 outbox row id.
func TestEnqueuePostsWithPartyAuthAndIdempotencyKey(t *testing.T) {
	g, wh, priv := fixture(t)
	resp, err := wh.Enqueue(context.Background(), wire.EnqueueWebhookRequest{
		To: "01HZXPROVIDER000001", Service: "curated-cohort",
		Payload: json.RawMessage(`{"op":"cohort-extract"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, webhookID, resp.WebhookID, "enqueue must decode the 202 outbox row id")

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/v1/webhooks", rec.Path)
	require.NotEmpty(t, rec.IdempotencyKey, "enqueue is an idempotent create (SDK-CLIENT-002)")
	assertSignedByClientPartyToken(t, rec, priv)
	var body wire.EnqueueWebhookRequest
	require.NoError(t, json.Unmarshal(rec.Body, &body))
	assert.Equal(t, "01HZXPROVIDER000001", body.To)
	assert.Equal(t, "curated-cohort", body.Service)
}

// TestSyncExposesQuotaRemainingVerbatim covers assertion 2: Sync
// POSTs /v1/webhooks/sync with party auth and exposes the relayed
// X-Quota-Remaining header verbatim.
func TestSyncExposesQuotaRemainingVerbatim(t *testing.T) {
	g, wh, priv := fixture(t)
	g.Script(http.MethodPost, "/v1/webhooks/sync", gatewaytest.ScriptStep{
		Status:  http.StatusOK,
		Headers: map[string]string{"X-Quota-Remaining": "17"},
	})
	resp, err := wh.Sync(context.Background(), wire.SyncWebhookRequest{
		To: "01HZXPROVIDER000001", Service: "metered-listing",
		Payload: json.RawMessage(`{"op":"invoke"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, resp.QuotaRemaining, "the relayed header must be exposed")
	assert.Equal(t, "17", *resp.QuotaRemaining, "the header value is verbatim")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the sync envelope decodes")
	assert.Equal(t, webhookID, resp.WebhookID)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	assert.Equal(t, http.MethodPost, recs[0].Method)
	assert.Equal(t, "/v1/webhooks/sync", recs[0].Path)
	require.NotEmpty(t, recs[0].IdempotencyKey, "sync is an idempotent create (SDK-CLIENT-002)")
	assertSignedByClientPartyToken(t, recs[0], priv)
}

// TestSyncQuotaRemainingNilWhenHeaderAbsent covers assertion 3: with
// no X-Quota-Remaining on the answer, QuotaRemaining stays nil.
func TestSyncQuotaRemainingNilWhenHeaderAbsent(t *testing.T) {
	g, wh, _ := fixture(t)
	resp, err := wh.Sync(context.Background(), wire.SyncWebhookRequest{
		To: "01HZXPROVIDER000001", Service: "metered-listing",
		Payload: json.RawMessage(`{"op":"invoke"}`),
	})
	require.NoError(t, err)
	assert.Nil(t, resp.QuotaRemaining, "no header means no provider metering answer")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Len(t, g.Recorded(), 1)
}

// TestSync402ReturnsAfterOneAttempt covers assertion 4: a terminal 402
// GW-HOOK-006 answer ends Sync after exactly one attempt even under a
// multi-attempt retry policy, as *wire.Error (SDK-RETRY-003).
func TestSync402ReturnsAfterOneAttempt(t *testing.T) {
	g, wh, _ := fixture(t, retryingPolicy)
	g.Script(http.MethodPost, "/v1/webhooks/sync", gatewaytest.ScriptStep{
		Status: http.StatusPaymentRequired, Body: []byte(hook006Body),
	})
	_, err := wh.Sync(context.Background(), wire.SyncWebhookRequest{
		To: "01HZXPROVIDER000001", Service: "metered-listing",
		Payload: json.RawMessage(`{"op":"invoke"}`),
	})
	require.Error(t, err)
	var werr *wire.Error
	require.ErrorAs(t, err, &werr, "a gateway failure surfaces as *wire.Error (SDK-CLIENT-003)")
	assert.Equal(t, "GW-HOOK-006", werr.Code, "the terminal 402 keeps its catalog code")
	assert.NotErrorIs(t, err, client.ErrOutcomeUnknown, "a terminal answer is a known outcome")
	assert.Len(t, g.Recorded(), 1, "the stop disposition must cost exactly one attempt")
}

// TestStatusGetsWithPartyAuth covers assertion 5: Status GETs
// /v1/webhooks/{id}/status with party auth and no Idempotency-Key (a
// read, not a create).
func TestStatusGetsWithPartyAuth(t *testing.T) {
	g, wh, priv := fixture(t)
	resp, err := wh.Status(context.Background(), webhookID)
	require.NoError(t, err)
	assert.Equal(t, "delivered", resp.State, "status must decode the canned row")
	assert.Equal(t, 1, resp.Attempts)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodGet, rec.Method)
	assert.Equal(t, "/v1/webhooks/"+webhookID+"/status", rec.Path)
	assertSignedByClientPartyToken(t, rec, priv)
	assert.Empty(t, rec.IdempotencyKey, "a read must not send an Idempotency-Key")
}

// TestResultPostsWithPartyAuthAndIdempotencyKey covers assertion 6:
// Result POSTs /v1/webhooks/{id}/result with party auth and an
// Idempotency-Key (the row requires one, SDK-API-002) and decodes the
// canned 202.
func TestResultPostsWithPartyAuthAndIdempotencyKey(t *testing.T) {
	g, wh, priv := fixture(t)
	resp, err := wh.Result(context.Background(), webhookID, wire.WebhookResultRequest{Result: "delivered"})
	require.NoError(t, err)
	assert.Equal(t, "accepted", resp.Status, "result must decode the 202 body")

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/v1/webhooks/"+webhookID+"/result", rec.Path)
	require.NotEmpty(t, rec.IdempotencyKey, "the result row requires a key (SDK-API-002)")
	assertSignedByClientPartyToken(t, rec, priv)
	var body wire.WebhookResultRequest
	require.NoError(t, json.Unmarshal(rec.Body, &body))
	assert.Equal(t, "delivered", body.Result)
}

// TestResultWithTicketSingleAttemptOn503 covers assertion 7 and the
// 503 half of assertion 8: the ticket route presents the ticket verbatim
// as the Bearer credential, makes exactly one attempt even when the
// bound client policy would retry a 503, wraps ErrOutcomeUnknown, and
// WithResponseMeta exposes the sent Idempotency-Key.
func TestResultWithTicketSingleAttemptOn503(t *testing.T) {
	g, wh, _ := fixture(t, retryingPolicy)
	g.Script(http.MethodPost, "/v1/webhooks/{id}/result", gatewaytest.ScriptStep{
		Status: http.StatusServiceUnavailable, Body: []byte(hook009Body),
	})
	ticket := "ks-result+jwt.single-use-ticket"
	var captured []client.ResponseMeta
	_, err := wh.ResultWithTicket(context.Background(), webhookID, ticket,
		wire.WebhookResultRequest{Result: "delivered"},
		WithResponseMeta(func(m client.ResponseMeta) { captured = append(captured, m) }))
	require.Error(t, err)
	assert.ErrorIs(t, err, client.ErrOutcomeUnknown, "503 GW-HOOK-009 after the one attempt is unknown")

	recs := g.Recorded()
	require.Len(t, recs, 1, "the ticket route makes exactly one attempt, whatever the client retry policy says")
	rec := recs[0]
	assert.Equal(t, "Bearer "+ticket, rec.Authorization, "the ticket is the Bearer credential, verbatim")
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/v1/webhooks/"+webhookID+"/result", rec.Path)
	require.NotEmpty(t, rec.IdempotencyKey, "each call carries one generated key (SDK-CLIENT-002)")

	require.Len(t, captured, 1, "WithResponseMeta observes the completed attempt")
	require.NotNil(t, captured[0].Header)
	assert.Equal(t, http.StatusServiceUnavailable, captured[0].Status)
	assert.Equal(t, rec.IdempotencyKey, captured[0].Header.Get("Idempotency-Key"),
		"the capture must expose the sent Idempotency-Key")
}

// TestResultWithTicketNetworkErrorIsUnknownOutcome covers the network
// half of assertion 8: a transport failure leaves the outcome unknown
// and WithResponseMeta still exposes the generated Idempotency-Key.
func TestResultWithTicketNetworkErrorIsUnknownOutcome(t *testing.T) {
	g, wh, _ := fixture(t)
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	deadWH, err := New(wh.cli, deadURL)
	require.NoError(t, err)

	ticket := "ks-result+jwt.single-use-ticket"
	var captured []client.ResponseMeta
	_, err = deadWH.ResultWithTicket(context.Background(), webhookID, ticket,
		wire.WebhookResultRequest{Result: "delivered"},
		WithResponseMeta(func(m client.ResponseMeta) { captured = append(captured, m) }))
	require.Error(t, err)
	assert.ErrorIs(t, err, client.ErrOutcomeUnknown, "a transport failure leaves the outcome unknown")
	require.Len(t, captured, 1, "WithResponseMeta observes the failed attempt")
	require.NotNil(t, captured[0].Header)
	assert.NotEmpty(t, captured[0].Header.Get("Idempotency-Key"), "the capture must expose the generated key")
	assert.Zero(t, captured[0].Status, "no response ever arrived")
	assert.Empty(t, g.Recorded(), "the request never reached the gateway")
}

// TestResultWithTicket401IsKnownOutcome covers assertion 9: a terminal
// 401 GW-HOOK-007 answer returns *wire.Error and never matches
// client.ErrOutcomeUnknown — a known outcome.
func TestResultWithTicket401IsKnownOutcome(t *testing.T) {
	g, wh, _ := fixture(t, retryingPolicy)
	g.Script(http.MethodPost, "/v1/webhooks/{id}/result", gatewaytest.ScriptStep{
		Status: http.StatusUnauthorized, Body: []byte(hook007Body),
	})
	_, err := wh.ResultWithTicket(context.Background(), webhookID, "ks-result+jwt.expired-ticket",
		wire.WebhookResultRequest{Result: "delivered"})
	require.Error(t, err)
	var werr *wire.Error
	require.ErrorAs(t, err, &werr, "the terminal answer surfaces as *wire.Error")
	assert.Equal(t, "GW-HOOK-007", werr.Code, "the rejection keeps its catalog code")
	assert.NotErrorIs(t, err, client.ErrOutcomeUnknown, "a rejected ticket is a known outcome")
	assert.Len(t, g.Recorded(), 1, "the rejection ends the route after one attempt")
}
