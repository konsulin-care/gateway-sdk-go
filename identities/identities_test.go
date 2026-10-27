package identities

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
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

// fixture wires a fake gateway, a client signed by an Ed25519 key, and an
// identities.Client bound to it; extra client options are appended last
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
	ids, err := New(cli)
	require.NoError(t, err)
	return g, ids, priv
}

// TestNewRejectsNilClient covers the constructor guard: a nil client
// fails New instead of deferring a nil panic to the first call.
func TestNewRejectsNilClient(t *testing.T) {
	ids, err := New(nil)
	require.Error(t, err)
	assert.Nil(t, ids)
}

// TestRegisterPostsWithPartyAuthAndIdempotencyKey covers assertion 1:
// Register POSTs /v1/identities/register with party auth and an
// Idempotency-Key and decodes the response DTO.
func TestRegisterPostsWithPartyAuthAndIdempotencyKey(t *testing.T) {
	g, ids, priv := fixture(t)
	resp, err := ids.Register(context.Background(), wire.RegisterIdentityRequest{
		PartyID: testPartyID, ResourceType: "patient",
		LocalResourceID: "fixture-patient-001",
		EmailHash:       "ZW1haWwtaGFzaC0wMDE=", PhoneHash: "N/A",
	})
	require.NoError(t, err)
	assert.Equal(t, "01HZYGLOBALKEY000001", resp.GlobalKey, "register must decode the response DTO")

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/v1/identities/register", rec.Path)
	require.NotEmpty(t, rec.IdempotencyKey, "register is an idempotent create (SDK-CLIENT-002)")
	require.True(t, strings.HasPrefix(rec.Authorization, "Bearer "), "register must carry a party token")
	pub := priv.Public().(ed25519.PublicKey)
	_, _, err = jws.VerifyEd25519(pub, []byte(strings.TrimPrefix(rec.Authorization, "Bearer ")))
	require.NoError(t, err, "register must be signed by the client signer")
	var body wire.RegisterIdentityRequest
	require.NoError(t, json.Unmarshal(rec.Body, &body))
	assert.Equal(t, "fixture-patient-001", body.LocalResourceID)
	assert.Equal(t, "patient", body.ResourceType)
}

// TestResolvePostsWithPartyAuthAndNoIdempotencyKey covers assertion 2:
// Resolve POSTs /v1/identities/resolve with party auth and no
// Idempotency-Key — resolve is a read, not a create.
func TestResolvePostsWithPartyAuthAndNoIdempotencyKey(t *testing.T) {
	g, ids, _ := fixture(t)
	resp, err := ids.Resolve(context.Background(), wire.ResolveIdentityRequest{
		EmailHash: "ZW1haWwtaGFzaC0wMDE=", PhoneHash: "N/A",
	})
	require.NoError(t, err)
	require.Len(t, resp.Candidates, 1, "resolve must decode the canned candidates")
	assert.Equal(t, "01HZYGLOBALKEY000001", resp.Candidates[0].GlobalKey)
	assert.Equal(t, "fixture-patient-001", resp.Candidates[0].LocalResourceID)
	assert.Equal(t, "email", resp.Candidates[0].MatchField)

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/v1/identities/resolve", rec.Path)
	assert.Empty(t, rec.IdempotencyKey, "resolve must not send an Idempotency-Key")
	require.True(t, strings.HasPrefix(rec.Authorization, "Bearer "), "resolve must carry a party token")
}

// TestLinkPostsWithPartyAuthAndIdempotencyKey covers assertion 3: Link
// POSTs /v1/identities/link with party auth and an Idempotency-Key.
func TestLinkPostsWithPartyAuthAndIdempotencyKey(t *testing.T) {
	g, ids, _ := fixture(t)
	resp, err := ids.Link(context.Background(), wire.LinkIdentityRequest{
		GlobalKey: "01HZYGLOBALKEY000001", LocalResourceID: "fixture-patient-001",
	})
	require.NoError(t, err)
	assert.True(t, resp.Linked, "link must decode {linked:true}")

	recs := g.Recorded()
	require.Len(t, recs, 1)
	rec := recs[0]
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/v1/identities/link", rec.Path)
	require.NotEmpty(t, rec.IdempotencyKey, "link is an idempotent create (SDK-CLIENT-002)")
	require.True(t, strings.HasPrefix(rec.Authorization, "Bearer "), "link must carry a party token")
}

// TestResolveRetries429Idx011ThenSucceeds covers assertion 4: a 429
// GW-IDX-011 on Resolve is retried (SDK-RETRY-002: the resolve quota
// classifies DispositionRetry) and the second attempt succeeds with the
// canned candidates.
func TestResolveRetries429Idx011ThenSucceeds(t *testing.T) {
	g, ids, _ := fixture(t, client.WithRetry(client.RetryPolicy{
		MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond,
	}))
	g.Script(http.MethodPost, "/v1/identities/resolve", gatewaytest.ScriptStep{
		Status: http.StatusTooManyRequests,
		Body:   []byte(`{"error":{"code":"GW-IDX-011","message":"resolve quota exceeded","request_id":"req-idx-011"}}`),
	})
	resp, err := ids.Resolve(context.Background(), wire.ResolveIdentityRequest{
		EmailHash: "ZW1haWwtaGFzaC0wMDE=", PhoneHash: "N/A",
	})
	require.NoError(t, err)
	require.Len(t, resp.Candidates, 1, "the retry must land on the canned 200")

	recs := g.Recorded()
	require.Len(t, recs, 2, "429 GW-IDX-011 must cost exactly one retry")
	assert.Equal(t, "/v1/identities/resolve", recs[0].Path)
	assert.Equal(t, "/v1/identities/resolve", recs[1].Path)
	assert.Empty(t, recs[0].IdempotencyKey)
	assert.Empty(t, recs[1].IdempotencyKey, "the retry must keep resolve keyless")
}
