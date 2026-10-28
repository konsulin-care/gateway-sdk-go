# gateway-sdk-go

The public Go client and verifier for the Konsulin gateway: enrollment and key
rotation, identity registration/resolution/linking, approval tickets, listings,
payments, webhook enqueue/sync/status/result, inbound callback verification
middleware, federation identity hashing, and the JWE envelope. Stdlib-only
runtime, MIT licensed — `go get github.com/konsulin-care/gateway-sdk-go`.

## Status

Pre-v0.1.0: the packages, docs and tooling are in place and the recipes below
run offline; requirement-by-requirement status lives in the PRD
[PROPOSAL.md](PROPOSAL.md) and the phase tasks under [docs/tasks/](docs/tasks/).

## Recipes (SDK-README-001)

Five runnable recipes: enrollment, signed calls, callback middleware, direct
exchange, and fetching the federation pepper. Every fenced block below is the
verbatim body of its `Example_*` function in
[internal/integration/readme_test.go](internal/integration/readme_test.go);
`TestReadmeRecipesMatchPublicAPI` extracts the five tagged blocks
(`go enrollment`, `go signed-calls`, `go callback`, `go exchange`,
`go pepper`) and fails if README and Example bodies drift apart. Each example
runs offline against the in-process [`gatewaytest`](gatewaytest/README.md)
fake — zero network:

```sh
go test -run Example ./internal/integration
```

The snippets are test-file code: `testPartyID` and `recipientPartyID` are the
fixture party ids, `exampleJSON` is a fatal-on-error `json.Marshal`, and the
`gatewaytest` servers stand in for the gateway. In production the same calls
target your gateway URL and your own keys.

### Enrollment

Register the party's Ed25519 signing key with its one-time enrollment token:
the SDK derives the kid (RFC 7638 thumbprint) and signs the request with a PoP
`body_sha256` over the exact bytes.

```go enrollment
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
```

### Signed calls

Party-signed requests: every attempt carries a fresh `ks-party+jwt` (a new
jti per attempt), and creates carry an `Idempotency-Key` so a 409 replay
reuses the same key (ADR-011).

```go signed-calls
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
```

### Callback middleware

Wrap the callback handler with `verify.Middleware`: every delivery must
carry a gateway-signed `ks-delivery+jwt` whose `body_sha256` covers the exact
body, whose `webhook_id` matches the `Webhook-Id` header, and whose replayed
`webhook_id` is answered 200 without touching the handler. The trailing half
of the block mints one delivery token the way the gateway would, to exercise
the middleware end to end.

```go callback
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
```

### Direct exchange

Mint an approval ticket for the recipient, let the recipient run the six-rule
check (`verify.Ticket`), then seal to the recipient's `use:enc` key and open
the compact JWE locally. The script block stands in for the gateway's
approval route in the offline example.

```go exchange
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
```

### Federation pepper

Fetch the federation pepper through the `federation-pepper` listing with a
sync (inline) invoke: keep the returned sealed JWE exactly as received —
sealed at rest — and at startup open it once with the party's X25519 private
key into memory only. The plaintext pepper is never written to disk or
environment.

```go pepper
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
```

## Development setup

```sh
mise install      # Go, golangci-lint, lefthook, govulncheck
mise run hooks    # install lefthook pre-commit and pre-push
mise run qc       # quality gate (format, lint, vet, lines, secret, deps, test, vuln)
go test ./...     # offline unit tests, zero network
```

## Contributing

See [AGENTS.md](AGENTS.md) for contract authority, navigation, security
invariants, boundaries, and conventions. The recipes above ship with their
tests — change a recipe and its `Example_*` body together;
`TestReadmeRecipesMatchPublicAPI` enforces the mirror.
