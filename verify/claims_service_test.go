package verify_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/verify"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// TestGoldenDeliveryServiceAndListingID asserts the mirrored golden
// delivery token surfaces the service and listing_id claims.
func TestGoldenDeliveryServiceAndListingID(t *testing.T) {
	v, fixtures := newGoldenVerifier(t, "pty-golden-engine")
	f := fixtures["ks-delivery.json"]
	got, err := v.Verify(context.Background(), goldenJWT(t, f), wire.TypDelivery, goldenBody(t, f))
	require.NoError(t, err)
	assert.Equal(t, "svc-golden", got.Service)
	assert.Equal(t, "lst-golden", got.ListingID)
}

// TestMiddlewareExposesServiceAndListingID asserts ClaimsFromContext
// carries Service and ListingID of the verified delivery token.
func TestMiddlewareExposesServiceAndListingID(t *testing.T) {
	env := newPerKindEnv(t, perKindSelf)
	body := []byte(`{"k":1}`)
	claims := deliveryClaims(env.now, perKindSelf, string(body))
	claims["service"] = "svc-x"
	claims["listing_id"] = "lst-x"
	tok := env.mint(t, wire.TypDelivery, claims)

	var got verify.Claims
	h := verify.Middleware(env.v, wire.TypDelivery)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = verify.ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newCallbackRequest(tok, body, nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "svc-x", got.Service)
	assert.Equal(t, "lst-x", got.ListingID)
}

// TestDeliveryWithoutServiceStillVerifies asserts the claims stay optional.
func TestDeliveryWithoutServiceStillVerifies(t *testing.T) {
	env := newPerKindEnv(t, perKindSelf)
	body := []byte(`{"k":2}`)
	tok := env.mint(t, wire.TypDelivery, deliveryClaims(env.now, perKindSelf, string(body)))
	got, err := env.v.Verify(context.Background(), tok, wire.TypDelivery, body)
	require.NoError(t, err)
	assert.Empty(t, got.Service)
	assert.Empty(t, got.ListingID)
}
