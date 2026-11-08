package listings

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// filterRecord is one captured request: method, path, and raw query.
// gatewaytest's RecordedRequest.Path drops the query (SDKP-007), so these
// tests read the query off a plain httptest server instead.
type filterRecord struct {
	method   string
	path     string
	rawQuery string
}

// fakeGateway is a plain httptest listings handler: it records each
// request's method, path, and raw query, then serves rows filtered by
// the name, provider_party_id, and invocation query params (GWP-005
// semantics). A missing or empty param matches every row.
type fakeGateway struct {
	mu   sync.Mutex
	last filterRecord
	rows []wire.ListingRow
}

// ServeHTTP records the request, filters the canned rows by the query
// params, and writes the resulting GetListingsResponse as JSON.
// Parameters: w — the response writer; r — the inbound request.
// Returns: nothing.
func (g *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.last = filterRecord{method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery}
	rows := g.rows
	g.mu.Unlock()

	q := r.URL.Query()
	matched := make([]wire.ListingRow, 0, len(rows))
	for _, row := range rows {
		if name := q.Get("name"); name != "" && row.Name != name {
			continue
		}
		if pid := q.Get("provider_party_id"); pid != "" && row.ProviderPartyID != pid {
			continue
		}
		if inv := q.Get("invocation"); inv != "" && row.Invocation != inv {
			continue
		}
		matched = append(matched, row)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(wire.GetListingsResponse{Listings: matched})
}

// lastRecord returns the most recent request recorded by the fake
// gateway. Parameters: none. Returns: the last captured filterRecord.
func (g *fakeGateway) lastRecord() filterRecord {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.last
}

// filterRows are the canned active listings the fake gateway filters
// over: two providers, one shared name, one webhook row — enough for a
// single match to be unique per provider+name pair.
var filterRows = []wire.ListingRow{
	{ListingID: "01HZYLISTING000001", ProviderPartyID: "01HZXPROVIDER000001",
		Name: "Webhook callback feed", Invocation: "webhook", Price: 1000,
		Currency: "IDR", PriceScope: "party", Metering: "gateway"},
	{ListingID: "01HZYLISTING000002", ProviderPartyID: "01HZXPROVIDER000001",
		Name: "Commodity extract", Invocation: "commodity", Price: 2000,
		Currency: "IDR", PriceScope: "user", Metering: "provider"},
	{ListingID: "01HZYLISTING000003", ProviderPartyID: "01HZXPROVIDER000002",
		Name: "Commodity extract", Invocation: "commodity", Price: 3000,
		Currency: "IDR", PriceScope: "user", Metering: "provider"},
}

// newFilterClient builds a listings.Client on a plain httptest.Server
// backed by a fake gateway serving the given rows. Parameters: t — the
// test; rows — the canned listing rows. Returns: the listings Client
// and its fake gateway.
func newFilterClient(t *testing.T, rows []wire.ListingRow) (*Client, *fakeGateway) {
	t.Helper()
	gw := &fakeGateway{rows: rows}
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)
	cli, err := client.New(client.WithBaseURL(srv.URL), client.WithInsecureTransport())
	require.NoError(t, err)
	ls, err := New(cli)
	require.NoError(t, err)
	return ls, gw
}

// TestListSendsFilterQueryParams covers assertion 1: List with options
// sends GET /v1/listings carrying name, provider_party_id, and
// invocation query params, and List without options sends no query
// string at all.
func TestListSendsFilterQueryParams(t *testing.T) {
	ls, gw := newFilterClient(t, filterRows)

	_, err := ls.List(context.Background(),
		WithName("Commodity extract"),
		WithProviderPartyID("01HZXPROVIDER000001"),
		WithInvocation("commodity"))
	require.NoError(t, err)

	rec := gw.lastRecord()
	assert.Equal(t, http.MethodGet, rec.method, "filters ride the public read")
	assert.Equal(t, "/v1/listings", rec.path)
	q, err := url.ParseQuery(rec.rawQuery)
	require.NoError(t, err)
	assert.Equal(t, "Commodity extract", q.Get("name"), "name must be sent as a query param")
	assert.Equal(t, "01HZXPROVIDER000001", q.Get("provider_party_id"),
		"provider_party_id must be sent as a query param")
	assert.Equal(t, "commodity", q.Get("invocation"), "invocation must be sent as a query param")

	_, err = ls.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, gw.lastRecord().rawQuery, "List without options must send no query string")
}

// TestFindByNameReturnsSingleMatch covers assertion 2: FindByName
// returns the single listing matching provider and name — the fake
// gateway filters on both params, so a dropped param yields two matches
// and fails the call.
func TestFindByNameReturnsSingleMatch(t *testing.T) {
	ls, _ := newFilterClient(t, filterRows)

	row, err := ls.FindByName(context.Background(), "01HZXPROVIDER000001", "Commodity extract")
	require.NoError(t, err)
	require.NotNil(t, row)
	assert.Equal(t, "01HZYLISTING000002", row.ListingID)
	assert.Equal(t, "01HZXPROVIDER000001", row.ProviderPartyID)
	assert.Equal(t, "Commodity extract", row.Name)
}

// TestFindByNameErrorsWhenNotExactlyOneMatch covers assertion 3:
// FindByName returns an error when zero or more than one listing
// matches the provider and name filters.
func TestFindByNameErrorsWhenNotExactlyOneMatch(t *testing.T) {
	t.Run("zero matches", func(t *testing.T) {
		ls, _ := newFilterClient(t, filterRows)
		row, err := ls.FindByName(context.Background(), "01HZXPROVIDER000001", "No such listing")
		require.Error(t, err, "zero matches must fail closed")
		assert.Nil(t, row)
	})

	t.Run("multiple matches", func(t *testing.T) {
		dupes := []wire.ListingRow{
			{ListingID: "01HZYLISTING000002", ProviderPartyID: "01HZXPROVIDER000001",
				Name: "Commodity extract", Invocation: "commodity", Price: 2000,
				Currency: "IDR", PriceScope: "user", Metering: "provider"},
			{ListingID: "01HZYLISTING000004", ProviderPartyID: "01HZXPROVIDER000001",
				Name: "Commodity extract", Invocation: "webhook", Price: 2500,
				Currency: "IDR", PriceScope: "party", Metering: "gateway"},
		}
		ls, _ := newFilterClient(t, dupes)
		row, err := ls.FindByName(context.Background(), "01HZXPROVIDER000001", "Commodity extract")
		require.Error(t, err, "ambiguity must fail closed")
		assert.Nil(t, row)
	})
}
