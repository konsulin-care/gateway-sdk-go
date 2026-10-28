package integration

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/approvals"
	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/envelope"
	"github.com/konsulin-care/gateway-sdk-go/gatewaytest"
	"github.com/konsulin-care/gateway-sdk-go/listings"
	"github.com/konsulin-care/gateway-sdk-go/parties"
	"github.com/konsulin-care/gateway-sdk-go/verify"
	"github.com/konsulin-care/gateway-sdk-go/webhooks"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// exampleFederationRecipe names the federation-pepper Example
// function, so the recipe map pairs the README tag with a named
// constant rather than a quoted literal on the tagged line.
const exampleFederationRecipe = "Example_federationPepper"

// readmeRecipes maps each tagged README Go recipe block to the Example
// function whose body the block must match after whitespace
// normalization (SDK-README-001).
var readmeRecipes = map[string]string{
	"enrollment":   "Example_enrollment",
	"signed-calls": "Example_signedCalls",
	"callback":     "Example_callbackMiddleware",
	"exchange":     "Example_directExchange",
	"pepper":       exampleFederationRecipe,
}

// TestReadmeRecipesMatchPublicAPI pins every tagged Go recipe block in
// README.md to its Example counterpart (SDK-README-001): README.md
// carries exactly five tagged blocks — enrollment, signed-calls,
// callback, exchange, pepper — each matches the body of its Example
// function after whitespace normalization, and the federation pepper
// recipe opens the sealed JWE with envelope.Open while writing nothing
// to disk or environment. The Example functions themselves run offline
// against gatewaytest as part of the package test binary (each carries
// an Output comment).
func TestReadmeRecipesMatchPublicAPI(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	require.NoError(t, err, "README.md must be readable from the package directory")
	blocks, order := extractTaggedGoBlocks(string(readme))
	require.Len(t, order, 5, "README.md must carry exactly five tagged Go recipe blocks")
	for _, tag := range order {
		require.Contains(t, readmeRecipes, tag, "unknown README recipe tag %q", tag)
	}
	for tag := range readmeRecipes {
		require.Contains(t, blocks, tag, "README.md must carry the %q recipe", tag)
	}

	const self = "readme_test.go"
	for tag, exampleName := range readmeRecipes {
		body := exampleFuncBody(t, self, exampleName)
		assert.Contains(t, normalizeSpace(body), normalizeSpace(blocks[tag]),
			"README %q recipe must match the body of %s after whitespace normalization",
			tag, exampleName)
	}

	pepper := blocks["pepper"]
	assert.Contains(t, pepper, "envelope.Open(",
		"the federation pepper recipe must open the sealed JWE with envelope.Open")
	for _, banned := range []string{
		"os.WriteFile", "os.Setenv", "os.Create", "os.OpenFile", "os.MkdirAll",
	} {
		assert.NotContains(t, pepper, banned,
			"the federation pepper recipe must keep the plaintext pepper in memory only")
	}
}

// extractTaggedGoBlocks scans Markdown source for fenced code blocks
// whose info string is "go <tag>" and returns their bodies by tag plus
// the tags in document order. Untagged fences (including plain ```go)
// are skipped, never treated as recipes.
//
// Parameters: src is the Markdown document.
// Returns: the block bodies keyed by tag, and the tags in order.
func extractTaggedGoBlocks(src string) (map[string]string, []string) {
	blocks := make(map[string]string)
	var order []string
	var buf []string
	tag, inBlock, inTagged := "", false, false
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case !inBlock && strings.HasPrefix(trimmed, "```go "):
			tag = strings.TrimSpace(strings.TrimPrefix(trimmed, "```go "))
			inBlock, inTagged, buf = true, true, nil
		case !inBlock:
			inBlock = strings.HasPrefix(trimmed, "```")
			inTagged = false
		case trimmed == "```" && inTagged:
			blocks[tag] = strings.Join(buf, "\n")
			order = append(order, tag)
			inBlock, inTagged = false, false
		case trimmed == "```":
			inBlock = false
		case inTagged:
			buf = append(buf, line)
		}
	}
	return blocks, order
}

// exampleFuncBody extracts the source between the braces of the named
// top-level function in filename, so a README block can be compared
// against the exact Example body text.
//
// Parameters: t is the test; filename is the Go source to parse; name
// is the function name to find.
// Returns: the function body text without the enclosing braces.
func exampleFuncBody(t *testing.T, filename, name string) string {
	t.Helper()
	src, err := os.ReadFile(filename)
	require.NoError(t, err)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	require.NoError(t, err)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Body.Lbrace).Offset
		end := fset.Position(fn.Body.Rbrace).Offset
		return string(src[start+1 : end])
	}
	t.Fatalf("function %s not found in %s", name, filename)
	return ""
}

// normalizeSpace collapses every whitespace run to one space, so a
// README block and its Example body compare regardless of indentation.
//
// Parameters: s is the text to normalize.
// Returns: the whitespace-normalized text.
func normalizeSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// exampleJSON marshals v for the offline examples, which have no
// *testing.T to fail: a marshal error aborts the example run.
//
// Parameters: v is the value to marshal.
// Returns: the JSON bytes.
func exampleJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

// Example_enrollment runs the README "enrollment" recipe offline against the
// gatewaytest fake (SDK-README-001); the tagged README block matches
// the recipe region of this body after whitespace normalization.
func Example_enrollment() {
	ctx := context.Background()
	g := gatewaytest.NewGateway()
	defer g.Close()
	gatewayURL := g.URL()
	partyID := "01HZYPARTY0000000000"
	enrollmentToken := "enroll-token-readme"
	cli, err := client.New(client.WithBaseURL(gatewayURL), client.WithInsecureTransport())
	if err != nil {
		log.Fatal(err)
	}

	// README "enrollment" recipe:
	// Generate the party's Ed25519 signing key — the SDK derives the kid
	// (RFC 7638 thumbprint) and signs the ks-party+jwt proof with a PoP
	// body_sha256 over the exact request bytes.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	pc, err := parties.New(cli, gatewayURL)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := pc.Enroll(ctx, parties.EnrollInput{
		PartyID: partyID, EnrollmentToken: enrollmentToken,
	}, priv)
	if err != nil {
		log.Fatal(err)
	}
	_, _ = fmt.Println("enrolled:", resp.PartyID)

	// Output:
	// enrolled: 01HZYPARTY0000000000
}

// Example_signedCalls runs the README "signed-calls" recipe offline
// against the gatewaytest fake (SDK-README-001).
func Example_signedCalls() {
	ctx := context.Background()
	g := gatewaytest.NewGateway()
	defer g.Close()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	cli, err := client.New(
		client.WithBaseURL(g.URL()),
		client.WithInsecureTransport(),
		client.WithSigner(testPartyID, priv),
	)
	if err != nil {
		log.Fatal(err)
	}

	// README "signed-calls" recipe:
	// Every attempt is signed fresh (a new jti per attempt); creates
	// carry an Idempotency-Key, so a 409 replay reuses the same key and
	// only a new logical create gets a new one (ADR-011).
	lc, err := listings.New(cli)
	if err != nil {
		log.Fatal(err)
	}
	out, err := lc.Create(ctx, wire.CreateListingRequest{
		Name:        "Curated pseudonymized research data",
		EndpointURL: "https://clinician.example.com/api/research/access",
		Price:       53200,
	})
	if err != nil {
		log.Fatal(err)
	}
	_, _ = fmt.Println("listing:", out.ListingID, out.State)

	// Output:
	// listing: 01HZYLISTING000001 active
}

// Example_callbackMiddleware runs the README "callback" recipe offline:
// a minted ks-delivery+jwt is served through the verify middleware and
// reaches the wrapped handler with verified claims (SDK-README-001).
func Example_callbackMiddleware() {
	minter, err := gatewaytest.NewMinter()
	if err != nil {
		log.Fatal(err)
	}
	doc, err := minter.JWKS()
	if err != nil {
		log.Fatal(err)
	}
	jwks, err := gatewaytest.NewJWKSServer(doc)
	if err != nil {
		log.Fatal(err)
	}
	defer jwks.Close()
	gatewayJWKSURL := jwks.URL()
	partyID := recipientPartyID

	// README "callback" recipe:
	// Wrap the callback handler with the verify middleware: every
	// delivery must carry a gateway-signed ks-delivery+jwt whose
	// body_sha256 covers the exact body and whose webhook_id claim the
	// Webhook-Id header matches; a replayed webhook_id answers 200
	// without touching the handler.
	verifier, err := verify.NewVerifier(gatewayJWKSURL, partyID)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/callbacks", func(w http.ResponseWriter, r *http.Request) {
		claims := verify.ClaimsFromContext(r.Context())
		_, _ = fmt.Println("verified delivery:", claims.WebhookID)
		w.WriteHeader(http.StatusNoContent)
	})
	handler := verify.Middleware(verifier, wire.TypDelivery)(mux)
	// Serve handler from your HTTP server, e.g.:
	// log.Fatal(http.ListenAndServe(":8080", handler))

	// Exercise the recipe: deliver one minted token to the handler.
	now := time.Now()
	body := []byte(`{"event":"payment.paid","amount":42}`)
	sum := sha256.Sum256(body)
	raw, err := exampleJSON(map[string]any{
		"iss":         "gateway",
		"aud":         partyID,
		"sub":         testPartyID,
		"purpose":     wire.PurposeWebhookDelivery,
		"webhook_id":  "wh-readme-callback-1",
		"body_sha256": base64.RawURLEncoding.EncodeToString(sum[:]),
		"iat":         now.Add(-time.Minute).Unix(),
		"exp":         now.Add(5 * time.Minute).Unix(),
	}), nil
	if err != nil {
		log.Fatal(err)
	}
	tok, err := minter.Mint(wire.TypDelivery, raw)
	if err != nil {
		log.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/callbacks", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	// Output:
	// verified delivery: wh-readme-callback-1
}

// Example_directExchange runs the README "exchange" recipe offline: the
// minted ticket passes the recipient's six-rule check (verify.Ticket)
// and the sealed payload opens byte-identical (SDK-README-001).
func Example_directExchange() {
	ctx := context.Background()
	g := gatewaytest.NewGateway()
	defer g.Close()
	minter, err := gatewaytest.NewMinter()
	if err != nil {
		log.Fatal(err)
	}
	doc, err := minter.JWKS()
	if err != nil {
		log.Fatal(err)
	}
	jwks, err := gatewaytest.NewJWKSServer(doc)
	if err != nil {
		log.Fatal(err)
	}
	defer jwks.Close()
	_, partyPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	cli, err := client.New(
		client.WithBaseURL(g.URL()),
		client.WithInsecureTransport(),
		client.WithSigner(testPartyID, partyPriv),
	)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := verify.NewVerifier(jwks.URL(), recipientPartyID)
	if err != nil {
		log.Fatal(err)
	}

	// Script the approval route with a real minted ticket.
	now := time.Now()
	jti := "jti-readme-exchange-1"
	ticket, err := minter.Mint(wire.TypApproval, exampleJSON(map[string]any{
		"iss":             "gateway",
		"aud":             recipientPartyID,
		"sub":             testPartyID,
		"scope":           "referral",
		"purpose":         "referral to study",
		"researcher_hash": "N/A",
		"jti":             jti,
		"iat":             now.Add(-time.Minute).Unix(),
		"exp":             now.Add(10 * time.Minute).Unix(),
	}))
	if err != nil {
		log.Fatal(err)
	}
	g.Script(http.MethodPost, "/v1/approvals", gatewaytest.ScriptStep{
		Status: http.StatusOK,
		Body: exampleJSON(wire.MintApprovalResponse{
			AccessToken: ticket, JTI: jti, ExpiresAt: now.Add(10 * time.Minute).UTC().Format(time.RFC3339),
		}),
	})

	// The recipient's use:enc key, published as a one-key JWKS.
	recipientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(recipientKey.PublicKey().Bytes())
	recipientKid := "readme-recipient-kid"
	recipientJWKS := exampleJSON(map[string]any{"keys": []map[string]any{{
		"kty": "OKP", "crv": "X25519", "use": "enc", "kid": recipientKid, "x": x,
	}}})

	// README "exchange" recipe:
	// Mint an approval ticket for the recipient, let the recipient run
	// the six-rule check (verify.Ticket), then seal to the recipient's
	// use:enc key and open the compact JWE locally.
	ac, err := approvals.New(cli)
	if err != nil {
		log.Fatal(err)
	}
	res, err := ac.Mint(ctx, wire.MintApprovalRequest{
		To: recipientPartyID, Scope: "referral", Purpose: "referral to study", TTL: 900,
	})
	if err != nil {
		log.Fatal(err)
	}
	claims, err := verifier.Ticket(ctx, res.AccessToken, wire.TypApproval, "referral")
	if err != nil {
		log.Fatal(err)
	}
	encKey, err := envelope.SelectEncKey(recipientJWKS, recipientKid)
	if err != nil {
		log.Fatal(err)
	}
	sealed, err := envelope.Seal([]byte(`{"study":"cohort-a"}`), recipientKid, encKey)
	if err != nil {
		log.Fatal(err)
	}
	opened, err := envelope.Open(sealed, recipientKey)
	if err != nil {
		log.Fatal(err)
	}
	_, _ = fmt.Println("exchange:", claims.Scope, string(opened))

	// Output:
	// exchange: referral {"study":"cohort-a"}
}

// Example_federationPepper runs the README "pepper" recipe offline: the
// sync-invoke of the federation-pepper listing returns a sealed JWE
// that is kept as received and opened into memory only
// (SDK-README-001).
func Example_federationPepper() {
	ctx := context.Background()
	g := gatewaytest.NewGateway()
	defer g.Close()
	gatewayURL := g.URL()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	cli, err := client.New(
		client.WithBaseURL(gatewayURL),
		client.WithInsecureTransport(),
		client.WithSigner(testPartyID, priv),
	)
	if err != nil {
		log.Fatal(err)
	}
	recipientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	pepperBytes := make([]byte, 32)
	for i := range pepperBytes {
		pepperBytes[i] = byte(i + 1)
	}
	sealed, err := envelope.Seal(pepperBytes, "readme-pepper-kid", recipientKey.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	g.Script(http.MethodPost, "/v1/webhooks/sync", gatewaytest.ScriptStep{
		Status: http.StatusOK,
		Body: exampleJSON(wire.SyncWebhookResponse{
			StatusCode: 200, Body: sealed, ContentType: "application/jose+jwt", WebhookID: "01JAV3Q6R7K9X2M4N8P0Q1S5T7",
		}),
	})

	// README "pepper" recipe:
	// Fetch the federation pepper through the federation-pepper listing
	// with a sync (inline) invoke and keep the sealed JWE exactly as
	// received — sealed at rest, never written to disk or environment.
	wh, err := webhooks.New(cli, gatewayURL)
	if err != nil {
		log.Fatal(err)
	}
	inv, err := wh.Sync(ctx, wire.SyncWebhookRequest{
		To: "01HZYPROVIDER00000001", Service: "federation-pepper", Payload: json.RawMessage(`{"subject":"user-123"}`),
	})
	if err != nil {
		log.Fatal(err)
	}
	sealedPepper := inv.Body // the sealed JWE, kept as received

	// At startup, open it once with the party's X25519 private key into
	// memory only — the plaintext pepper never touches disk or env.
	pepper, err := envelope.Open(sealedPepper, recipientKey)
	if err != nil {
		log.Fatal(err)
	}
	_, _ = fmt.Println("pepper bytes:", len(pepper))

	// Output:
	// pepper bytes: 32
}
