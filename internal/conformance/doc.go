// Package conformance holds the shared conformance cases executed by
// cmd/conformance against a live gateway: positive flows over the QC-chain
// party surface plus the negative cases (wrong key, replay, wrong typ,
// body_sha256 mismatch, expiry, unknown kid, revoked party, capability
// denial, idempotency replay).
//
// This file also carries the helpers every case shares: the SDK and
// domain client builders, thumbprint, and identity-hash helpers the
// positive chain builds on, and the raw probe/deny harness plus the
// hand-crafted token builders the negative cases probe with.
//
// Allowed imports: standard library and public SDK packages (PRD §7
// dependency rules).
//
// Requirement IDs: SDK-CONF-001, SDK-CONF-002, SDK-CONF-003, SDK-CONF-C01.
package conformance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/konsulin-care/gateway-sdk-go/approvals"
	"github.com/konsulin-care/gateway-sdk-go/auth"
	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/gateway"
	"github.com/konsulin-care/gateway-sdk-go/identities"
	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/listings"
	"github.com/konsulin-care/gateway-sdk-go/parties"
	"github.com/konsulin-care/gateway-sdk-go/payments"
	"github.com/konsulin-care/gateway-sdk-go/webhooks"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// edThumbprint computes the RFC 7638 thumbprint of an Ed25519 public
// key — the kid the conformance cases assign their keys.
func edThumbprint(pub ed25519.PublicKey) (string, error) {
	key := jwk.Key{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
	return key.Thumbprint()
}

// sdkClient builds the SDK client every positive step issues through:
// the env base URL and HTTP client, the env party signer when the chain
// key is set, and the insecure-transport opt-in for plain-http targets.
func sdkClient(env *Env) (*client.Client, error) {
	opts := []client.Option{
		client.WithBaseURL(env.BaseURL),
		client.WithHTTPClient(env.client()),
	}
	if len(env.Priv) > 0 {
		opts = append(opts, client.WithSigner(env.PartyID, env.Priv))
	}
	if u, err := url.Parse(env.BaseURL); err == nil && u.Scheme == "http" {
		opts = append(opts, client.WithInsecureTransport())
	}
	return client.New(opts...)
}

// gatewayClient returns the chain gateway client for env or the named error.
func gatewayClient(env *Env, name string) (*gateway.Client, error) {
	cli, err := sdkClient(env)
	if err != nil {
		return nil, named(name, err)
	}
	gw, err := gateway.New(cli)
	if err != nil {
		return nil, named(name, err)
	}
	return gw, nil
}

// partiesClient returns the chain parties client for env or the named error.
func partiesClient(env *Env, name string) (*parties.Client, error) {
	cli, err := sdkClient(env)
	if err != nil {
		return nil, named(name, err)
	}
	pc, err := parties.New(cli, env.BaseURL)
	if err != nil {
		return nil, named(name, err)
	}
	return pc, nil
}

// identitiesClient returns the chain identities client for env or the named error.
func identitiesClient(env *Env, name string) (*identities.Client, error) {
	cli, err := sdkClient(env)
	if err != nil {
		return nil, named(name, err)
	}
	ic, err := identities.New(cli)
	if err != nil {
		return nil, named(name, err)
	}
	return ic, nil
}

// approvalsClient returns the chain approvals client for env or the named error.
func approvalsClient(env *Env, name string) (*approvals.Client, error) {
	cli, err := sdkClient(env)
	if err != nil {
		return nil, named(name, err)
	}
	ac, err := approvals.New(cli)
	if err != nil {
		return nil, named(name, err)
	}
	return ac, nil
}

// listingsClient returns the chain listings client for env or the named error.
func listingsClient(env *Env, name string) (*listings.Client, error) {
	cli, err := sdkClient(env)
	if err != nil {
		return nil, named(name, err)
	}
	lc, err := listings.New(cli)
	if err != nil {
		return nil, named(name, err)
	}
	return lc, nil
}

// paymentsClient returns the chain payments client for env or the named error.
func paymentsClient(env *Env, name string) (*payments.Client, error) {
	cli, err := sdkClient(env)
	if err != nil {
		return nil, named(name, err)
	}
	pay, err := payments.New(cli)
	if err != nil {
		return nil, named(name, err)
	}
	return pay, nil
}

// webhooksClient returns the chain webhooks client for env or the named error.
func webhooksClient(env *Env, name string) (*webhooks.Client, error) {
	cli, err := sdkClient(env)
	if err != nil {
		return nil, named(name, err)
	}
	wh, err := webhooks.New(cli, env.BaseURL)
	if err != nil {
		return nil, named(name, err)
	}
	return wh, nil
}

// identityHash builds the deterministic base64 identity hash the
// identity steps register, resolve, and link.
func identityHash(field string) string {
	sum := sha256.Sum256([]byte(field))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// probe issues one raw HTTP request against env and returns the status
// and bounded response body; bearer and idemKey are set only when non-empty.
func probe(ctx context.Context, env *Env, method, path, bearer, idemKey string, body []byte) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, env.BaseURL+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := env.client().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, err
}

// expectDeny requires the response to carry wantStatus and a gateway
// error envelope whose code equals wantCode — the observed deny.
func expectDeny(status int, body []byte, wantStatus int, wantCode string) error {
	if status != wantStatus {
		return fmt.Errorf("status %d, want deny %d (body %.200q)", status, wantStatus, body)
	}
	if got := wire.DecodeError(status, body); got.Code != wantCode {
		return fmt.Errorf("deny code %q, want %q", got.Code, wantCode)
	}
	return nil
}

// named wraps err with the case name; nil passes through unchanged. The
// cases use it inline to keep their probes free of wrap boilerplate.
func named(name string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("conformance: %s: %w", name, err)
}

// partyPath builds a concrete party-route path over the env party id.
func partyPath(env *Env, suffix string) string {
	return "/v1/parties/" + url.PathEscape(env.PartyID) + suffix
}

// probeKey returns the chain signing key, or a fresh key when the chain
// has not enrolled one (the offline probes never need the chain key).
func probeKey(env *Env) (ed25519.PrivateKey, error) {
	if len(env.Priv) > 0 {
		return env.Priv, nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// claimsNow builds ks-party+jwt claims for the env party.
func claimsNow(partyID string, iat, exp int64) (auth.PartyClaims, error) {
	jti, err := auth.NewJti()
	if err != nil {
		return auth.PartyClaims{}, err
	}
	return auth.PartyClaims{Aud: "gateway", Exp: exp, Iat: iat, Iss: partyID, Jti: jti}, nil
}

// signParty hand-crafts a compact JWS with an arbitrary typ — an empty
// typ omits the member entirely (jws.Header is omitempty).
func signParty(priv ed25519.PrivateKey, typ string, claims auth.PartyClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("conformance: public key type %T", priv.Public())
	}
	kid, err := edThumbprint(pub)
	if err != nil {
		return "", err
	}
	return jws.SignEd25519(priv, jws.Header{Alg: jws.AlgEdDSA, Kid: kid, Typ: typ}, payload)
}

// partyToken builds a party probe token for env with the given typ: a
// fresh (or the chain) Ed25519 key, current claims, and a hand-crafted
// JWS whose header carries typ verbatim.
func partyToken(env *Env, typ string) (string, error) {
	priv, err := probeKey(env)
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	claims, err := claimsNow(env.PartyID, now, now+auth.MaxPartyLifetime)
	if err != nil {
		return "", err
	}
	return signParty(priv, typ, claims)
}

// readJWKS performs the one unknown-kid JWKS refetch the cases model.
func readJWKS(ctx context.Context, env *Env, name string) error {
	status, body, err := probe(ctx, env, http.MethodGet, partyPath(env, "/jwks"), "", "", nil)
	if err != nil {
		return fmt.Errorf("conformance: %s: jwks read: %w", name, err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("conformance: %s: jwks read status %d (body %.200q)", name, status, body)
	}
	return nil
}
