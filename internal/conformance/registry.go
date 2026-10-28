package conformance

import (
	"context"
	"crypto/ed25519"
	"net/http"

	"github.com/konsulin-care/gateway-sdk-go/internal/adminboot"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// Kind classifies a conformance case: a positive QC-chain step or a
// negative deny observation.
type Kind string

// The two case kinds the registry distinguishes.
const (
	// KindPositive marks a QC-chain happy-path step (SDK-CONF-001).
	KindPositive Kind = "positive"
	// KindNegative marks a deny observation (SDK-CONF-002).
	KindNegative Kind = "negative"
)

// Case is one named conformance case: its unique name, its kind, and
// the run function executed against a target. Run returns nil when the
// case passes and a non-nil error naming the case (and the mismatch)
// when it fails — the runner turns that into the non-zero exit of
// SDK-CONF-C01.
type Case struct {
	// Name is the unique case name surfaced in reports and failures.
	Name string
	// Kind is the case kind (positive or negative).
	Kind Kind
	// Run executes the case against env; nil is pass, non-nil is fail.
	Run func(ctx context.Context, env *Env) error
}

// Env is the conformance target environment every case runs against:
// the live gateway base URL, its HTTP client, the bootstrap party
// context the positive chain threads between steps, and the plain-HTTP
// callback receiver the result-callback case observes.
type Env struct {
	// BaseURL is the live gateway base URL (scheme://host[:port]).
	BaseURL string
	// PartyHealthURL is the QC-chain party's health URL the bootstrap
	// case registers as endpoints.health on the create-party request;
	// empty selects the container-internal default for the throwaway
	// conformance gateway.
	PartyHealthURL string
	// CallbackURL is the runner's externally reachable result-callback
	// URL the bootstrap case registers as endpoints.callbacks; empty
	// falls back to the receiver's loopback URL.
	CallbackURL string
	// HTTP is the client every request is issued through (nil selects
	// http.DefaultClient).
	HTTP *http.Client
	// PartyID is the QC-chain party; the bootstrap case fills it and
	// later positive steps consume it.
	PartyID string
	// EnrollmentToken is the single-use token the bootstrap case
	// issues and the enrollment step consumes.
	EnrollmentToken string
	// AdminUser is the operator username for the admin bootstrap.
	AdminUser string
	// AdminPass is the operator password for the admin bootstrap.
	AdminPass string
	// Priv is the QC-chain party's active Ed25519 signing key: the
	// enrollment case registers it, the rotation case installs a fresh
	// replacement, and the signed party routes sign with it. Bootstrap
	// leaves it unset.
	Priv ed25519.PrivateKey
	// ListingID is the free listing the listings case creates and the
	// payment-paid case purchases. Empty until the listings step runs.
	ListingID string
	// ListingService is the created listing's service name — the
	// marketplace title the webhooks step enqueues against. Empty
	// until the listings step runs.
	ListingService string
	// Callback is the plain-HTTP result receiver; the result-callback
	// case passes only after at least one inbound delivery is recorded.
	Callback *CallbackReceiver
}

// client returns the env's HTTP client, selecting the default when unset.
func (e *Env) client() *http.Client {
	if e != nil && e.HTTP != nil {
		return e.HTTP
	}
	return http.DefaultClient
}

// defaultPartyHealthURL is the party health endpoint the bootstrap
// case registers when Env.PartyHealthURL is unset: the container-
// internal throwaway conformance gateway's loopback health route.
const defaultPartyHealthURL = "http://127.0.0.1:8080/health"

// conformanceListingName is the QC-chain free listing's marketplace
// title; the gateway resolves a webhook's service field against
// listing names, so it doubles as the chain listing's service name.
const conformanceListingName = "conformance-free-listing"

// partyHealthURL returns the configured party health URL, selecting
// the container-internal default when the env leaves it unset.
//
// Returns: the endpoints.health URL for the create-party request.
func (e *Env) partyHealthURL() string {
	if e != nil && e.PartyHealthURL != "" {
		return e.PartyHealthURL
	}
	return defaultPartyHealthURL
}

// callbackURL returns the runner's externally reachable callback URL
// from the env, falling back to the receiver's loopback URL when
// unset, and empty when neither is configured.
//
// Returns: the endpoints.callbacks URL for the create-party request.
func (e *Env) callbackURL() string {
	if e == nil {
		return ""
	}
	if e.CallbackURL != "" {
		return e.CallbackURL
	}
	if e.Callback != nil {
		return e.Callback.URL()
	}
	return ""
}

// revokeWebhookInvoke revokes the env party's webhook:invoke grant at
// DELETE /v1/admin/parties/{id}/capabilities/webhook:invoke after a
// fresh adminboot login, so the capability-denied probe arrives
// strictly after the revoke.
//
// Parameters: ctx bounds the admin calls; name is the case name the
// wrapped failures carry.
// Returns: nil when the login and the revoke both succeed, or the
// failure.
func (e *Env) revokeWebhookInvoke(ctx context.Context, name string) error {
	ab := adminboot.New(e.BaseURL, e.client())
	bearer, err := ab.Login(ctx, e.AdminUser, e.AdminPass)
	if err != nil {
		return named(name+": admin login", err)
	}
	if err := ab.RevokeCapability(ctx, bearer, e.PartyID, wire.CapabilityWebhookInvoke); err != nil {
		return named(name+": revoke webhook:invoke", err)
	}
	return nil
}

// revokeParty revokes the env party at POST /v1/admin/parties/{id}/
// revoke after a fresh adminboot login, so the revoked-party probe
// arrives strictly after the revoke.
//
// Parameters: ctx bounds the admin calls; name is the case name the
// wrapped failures carry.
// Returns: nil when the login and the revoke both succeed, or the
// failure.
func (e *Env) revokeParty(ctx context.Context, name string) error {
	ab := adminboot.New(e.BaseURL, e.client())
	bearer, err := ab.Login(ctx, e.AdminUser, e.AdminPass)
	if err != nil {
		return named(name+": admin login", err)
	}
	if err := ab.RevokeParty(ctx, bearer, e.PartyID); err != nil {
		return named(name+": revoke party", err)
	}
	return nil
}

// QCChainNames is the SDK-CONF-001 QC-chain step list in chain order:
// gateway health, admin bootstrap (login → create party → issue
// enrollment token), then enrollment, rotation, JWKS, identities,
// approvals, listings, the free-listing payment reaching PAID,
// webhooks, and the result callback.
var QCChainNames = []string{
	"health",
	"bootstrap",
	"enrollment",
	"rotation",
	"jwks",
	"identities",
	"approvals",
	"listings",
	"payment-paid",
	"webhooks",
	"result-callback",
}

// NegativeNames is the SDK-CONF-002 negative case list in registry
// order: wrong signing key, replayed enrollment token, wrong typ,
// body_sha256 mismatch, expired token, unknown kid after one refetch,
// idempotency replay (byte-identical response), missing capability
// (capability_denied) after the webhook:invoke revoke, and revoked
// party after the admin party revoke. The three terminal cases run
// last in that order: the replay still needs the granted capability,
// and revoking the party ends the run.
var NegativeNames = []string{
	"wrong-signing-key",
	"replayed-enrollment-token",
	"wrong-typ",
	"body-sha256-mismatch",
	"expired-token",
	"unknown-kid",
	"idempotency-replay",
	"capability-denied",
	"revoked-party",
}

// positiveCases builds the ordered positive QC-chain cases.
func positiveCases() []Case {
	return []Case{
		{Name: "health", Kind: KindPositive, Run: runHealth},
		{Name: "bootstrap", Kind: KindPositive, Run: runBootstrap},
		{Name: "enrollment", Kind: KindPositive, Run: runEnrollment},
		{Name: "rotation", Kind: KindPositive, Run: runRotation},
		{Name: "jwks", Kind: KindPositive, Run: runJWKS},
		{Name: "identities", Kind: KindPositive, Run: runIdentities},
		{Name: "approvals", Kind: KindPositive, Run: runApprovals},
		{Name: "listings", Kind: KindPositive, Run: runListings},
		{Name: "payment-paid", Kind: KindPositive, Run: runPaymentPaid},
		{Name: "webhooks", Kind: KindPositive, Run: runWebhooks},
		{Name: "result-callback", Kind: KindPositive, Run: runResultCallback},
	}
}

// negativeCases builds the ordered SDK-CONF-002 deny cases: every
// NegativeNames entry paired with its run function, ending in the
// idempotency replay and the two admin-revoke observations.
func negativeCases() []Case {
	return []Case{
		{Name: "wrong-signing-key", Kind: KindNegative, Run: negativeWrongSigningKey},
		{Name: "replayed-enrollment-token", Kind: KindNegative, Run: negativeReplayedEnrollmentToken},
		{Name: "wrong-typ", Kind: KindNegative, Run: negativeWrongTyp},
		{Name: "body-sha256-mismatch", Kind: KindNegative, Run: negativeBodySHA256Mismatch},
		{Name: "expired-token", Kind: KindNegative, Run: negativeExpiredToken},
		{Name: "unknown-kid", Kind: KindNegative, Run: negativeUnknownKid},
		{Name: "idempotency-replay", Kind: KindNegative, Run: negativeIdempotencyReplay},
		{Name: "capability-denied", Kind: KindNegative, Run: negativeCapabilityDenied},
		{Name: "revoked-party", Kind: KindNegative, Run: negativeRevokedParty},
	}
}

// Registry returns the full ordered case registry: the positive
// QC-chain steps in SDK-CONF-001 chain order followed by the negative
// SDK-CONF-002 cases. Every name is unique; the returned slice is a
// fresh copy and mutating it never affects the package.
func Registry() []Case {
	pos := positiveCases()
	neg := negativeCases()
	out := make([]Case, 0, len(pos)+len(neg))
	out = append(out, pos...)
	out = append(out, neg...)
	return out
}
