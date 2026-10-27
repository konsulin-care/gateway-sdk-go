package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/approvals"
	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/gateway"
	"github.com/konsulin-care/gateway-sdk-go/gatewaytest"
	"github.com/konsulin-care/gateway-sdk-go/identities"
	"github.com/konsulin-care/gateway-sdk-go/listings"
	"github.com/konsulin-care/gateway-sdk-go/parties"
	"github.com/konsulin-care/gateway-sdk-go/payments"
	"github.com/konsulin-care/gateway-sdk-go/webhooks"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// The concrete path-parameter ids every invoker uses; each row's expected
// path is derived from wire.RouteTable() by substituting these for "{id}".
const (
	testPartyID   = "01HZYPARTY0000000000"
	testPaymentID = "01HZYPAYMENT000001"
	testWebhookID = "01JAV3Q6R7K9X2M4N8P0Q1S5T7"
)

// TestRouteTableRowsThroughTypedFunctions covers SDK-API-001 and
// SDK-API-002 (cross-route): every wire.RouteTable() row is invoked
// through its typed package function against gatewaytest, and the
// recorder shows the row's verb and path, exactly one request, an
// Idempotency-Key on every flagged row (and none anywhere else), no
// Authorization on the public rows, and a ks-party+jwt bearer on the
// party rows. Offline, zero network.
func TestRouteTableRowsThroughTypedFunctions(t *testing.T) {
	g, invokers := routeFixture(t)
	ctx := context.Background()
	rows := wire.RouteTable()
	require.NotEmpty(t, rows, "the route table must not be empty")
	require.Len(t, invokers, len(rows), "every route-table row needs exactly one typed invoker")

	for _, row := range rows {
		t.Run(row.Package+"."+row.Method, func(t *testing.T) {
			invoke, ok := invokers[row.Package+"/"+row.Method]
			require.True(t, ok, "no typed invoker registered for %s.%s", row.Package, row.Method)

			before := len(g.Recorded())
			require.NoError(t, invoke(ctx), "%s.%s must succeed against gatewaytest", row.Package, row.Method)
			recs := g.Recorded()
			require.Len(t, recs, before+1, "%s.%s must send exactly one request", row.Package, row.Method)
			rec := recs[before]

			// Assertion 1: the recorder shows the row's verb and path.
			assert.Equal(t, row.Verb, rec.Method, "%s.%s verb", row.Package, row.Method)
			assert.Equal(t, strings.ReplaceAll(row.Path, "{id}", pathID(row.Path)), rec.Path,
				"%s.%s path", row.Package, row.Method)

			// Assertion 2: an Idempotency-Key on flagged rows, none elsewhere.
			if row.IdempotencyRequired {
				assert.NotEmpty(t, rec.IdempotencyKey,
					"%s.%s must send an Idempotency-Key (SDK-API-002)", row.Package, row.Method)
			} else {
				assert.Empty(t, rec.IdempotencyKey,
					"%s.%s must not send an Idempotency-Key", row.Package, row.Method)
			}

			// Assertion 3: party rows send a ks-party+jwt bearer; public
			// rows send no Authorization — except the enrollment row,
			// whose PoP proof is the row's documented credential
			// (wire.AuthPublic: "enrollment with its proof"). The ticket
			// row is credentialled by its single-use ticket, so the
			// contract asserts only its Idempotency-Key above.
			switch row.Auth {
			case wire.AuthParty:
				requireKSPartyBearer(t, rec, row)
			case wire.AuthPublic:
				if row.Package == "parties" && row.Method == "Enroll" {
					requireKSPartyBearer(t, rec, row)
				} else {
					assert.Empty(t, rec.Authorization,
						"%s.%s is public: no Authorization header", row.Package, row.Method)
				}
			case wire.AuthTicket:
				// No Authorization assertion: the ticket is the credential.
			default:
				t.Fatalf("unexpected auth class %q on %s.%s", row.Auth, row.Package, row.Method)
			}
		})
	}
}

// requireKSPartyBearer asserts that rec carries the row's
// "Authorization: Bearer" credential: a compact JWS whose protected
// header declares the exact ks-party+jwt typ and whose payload carries
// the jti the recorder surfaced undecoded.
// Parameters: t is the test; rec is the recorded request; row names the
// row in failure messages. Fails the test on any mismatch.
func requireKSPartyBearer(t *testing.T, rec gatewaytest.RecordedRequest, row wire.Route) {
	t.Helper()
	require.True(t, strings.HasPrefix(rec.Authorization, "Bearer "),
		"%s %s must send a Bearer credential", row.Verb, row.Path)
	token := strings.TrimPrefix(rec.Authorization, "Bearer ")
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "%s %s credential must be a compact JWS", row.Verb, row.Path)
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err, "%s %s protected header must be base64url", row.Verb, row.Path)
	var hdr struct {
		Typ string `json:"typ"`
	}
	require.NoError(t, json.Unmarshal(raw, &hdr), "%s %s protected header must be JSON", row.Verb, row.Path)
	assert.Equal(t, wire.TypParty, hdr.Typ, "%s %s must send typ ks-party+jwt", row.Verb, row.Path)
	require.NotEmpty(t, rec.PartyJTI, "%s %s token must carry a jti claim", row.Verb, row.Path)
}

// pathID returns the concrete id every invoker substitutes for the "{id}"
// parameter of one route pattern, so the expected path is derived from
// the table row itself rather than restated per call.
// Parameters: pattern is the row's path pattern.
// Returns: the payment id for payment paths, the webhook id for webhook
// paths, the party id otherwise.
func pathID(pattern string) string {
	switch {
	case strings.Contains(pattern, "/payments/"):
		return testPaymentID
	case strings.Contains(pattern, "/webhooks/"):
		return testWebhookID
	default:
		return testPartyID
	}
}

// routeFixture wires one fake gateway, one client configured with a
// party signer, and every typed route client; it returns the fake plus
// one invoker per wire.RouteTable() row keyed "package/Method". Each
// invoker calls its typed package function and returns the error.
// Parameters: t is the test (registers cleanup).
// Returns: the fake gateway and the invoker map.
func routeFixture(t *testing.T) (*gatewaytest.Gateway, map[string]func(context.Context) error) {
	t.Helper()
	g := gatewaytest.NewGateway()
	t.Cleanup(g.Close)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cli, err := client.New(
		client.WithBaseURL(g.URL()),
		client.WithInsecureTransport(),
		client.WithSigner(testPartyID, priv),
	)
	require.NoError(t, err)
	pc, err := parties.New(cli, g.URL())
	require.NoError(t, err)
	wc, err := webhooks.New(cli, g.URL())
	require.NoError(t, err)
	ic, err := identities.New(cli)
	require.NoError(t, err)
	ac, err := approvals.New(cli)
	require.NoError(t, err)
	lc, err := listings.New(cli)
	require.NoError(t, err)
	pyc, err := payments.New(cli)
	require.NoError(t, err)
	gwc, err := gateway.New(cli)
	require.NoError(t, err)

	return g, map[string]func(context.Context) error{
		"parties/Enroll": func(ctx context.Context) error {
			_, err := pc.Enroll(ctx, parties.EnrollInput{
				PartyID: testPartyID, EnrollmentToken: "enroll-token-001",
			}, priv)
			return err
		},
		"parties/Rotate": func(ctx context.Context) error {
			_, err := pc.Rotate(ctx, testPartyID, wire.RotateKeyRequest{
				PublicKey: "cGFydHkta2V5LXB1YmxpYy0wMDE=", Kid: "qc-party-kid-2",
			})
			return err
		},
		"parties/JWKS":   func(ctx context.Context) error { _, err := pc.JWKS(ctx, testPartyID); return err },
		"parties/Health": func(ctx context.Context) error { _, err := pc.Health(ctx, testPartyID); return err },
		"identities/Register": func(ctx context.Context) error {
			_, err := ic.Register(ctx, wire.RegisterIdentityRequest{
				ResourceType: "patient", LocalResourceID: "fixture-patient-001",
				EmailHash: "N/A", PhoneHash: "N/A",
			})
			return err
		},
		"identities/Resolve": func(ctx context.Context) error {
			_, err := ic.Resolve(ctx, wire.ResolveIdentityRequest{EmailHash: "N/A", PhoneHash: "N/A"})
			return err
		},
		"identities/Link": func(ctx context.Context) error {
			_, err := ic.Link(ctx, wire.LinkIdentityRequest{
				GlobalKey: "01HZYGLOBALKEY000001", LocalResourceID: "fixture-patient-001",
			})
			return err
		},
		"approvals/Mint": func(ctx context.Context) error {
			_, err := ac.Mint(ctx, wire.MintApprovalRequest{
				To: "01HZYRECIPIENT000001", Scope: "referral",
				Purpose: "referral to study", TTL: 900,
			})
			return err
		},
		"listings/Create": func(ctx context.Context) error {
			_, err := lc.Create(ctx, wire.CreateListingRequest{
				Name:        "Curated pseudonymized research data",
				EndpointURL: "https://clinician.example.com/api/research/access",
				Price:       53200,
			})
			return err
		},
		"listings/List": func(ctx context.Context) error { _, err := lc.List(ctx); return err },
		"payments/Create": func(ctx context.Context) error {
			_, err := pyc.Create(ctx, wire.CreatePaymentRequest{ListingID: "01HZYLISTING000001"})
			return err
		},
		"payments/Get":         func(ctx context.Context) error { _, err := pyc.Get(ctx, testPaymentID); return err },
		"payments/AccessToken": func(ctx context.Context) error { _, err := pyc.AccessToken(ctx, testPaymentID); return err },
		"webhooks/Enqueue": func(ctx context.Context) error {
			_, err := wc.Enqueue(ctx, wire.EnqueueWebhookRequest{
				To: "01HZYPROVIDER000001", Service: "research-data",
				Payload: json.RawMessage(`{"query":"cohort"}`),
			})
			return err
		},
		"webhooks/Sync": func(ctx context.Context) error {
			_, err := wc.Sync(ctx, wire.SyncWebhookRequest{
				To: "01HZYPROVIDER000001", Service: "research-data",
				Payload: json.RawMessage(`{"query":"cohort"}`),
			})
			return err
		},
		"webhooks/Status": func(ctx context.Context) error { _, err := wc.Status(ctx, testWebhookID); return err },
		"webhooks/Result": func(ctx context.Context) error {
			_, err := wc.Result(ctx, testWebhookID, wire.WebhookResultRequest{Result: "success"})
			return err
		},
		"gateway/JWKS":   func(ctx context.Context) error { _, err := gwc.JWKS(ctx); return err },
		"gateway/Health": func(ctx context.Context) error { _, err := gwc.Health(ctx); return err },
	}
}
