package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/konsulin-care/gateway-sdk-go/internal/adminboot"
	"github.com/konsulin-care/gateway-sdk-go/parties"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// runHealth probes gateway health at GET /health and requires "ok".
func runHealth(ctx context.Context, env *Env) error {
	gw, err := gatewayClient(env, "health")
	if err != nil {
		return err
	}
	out, err := gw.Health(ctx)
	if err != nil {
		return named("health", err)
	}
	if out.Status != "ok" {
		return fmt.Errorf("conformance: health: status %q, want %q", out.Status, "ok")
	}
	return nil
}

// runBootstrap performs the admin bootstrap over internal/adminboot —
// login, create party (carrying endpoints.health and
// endpoints.callbacks), issue the single-use enrollment token — and
// threads party id and token into env. Bootstrap issues the token
// only: it grants no capabilities, because the chain party earns its
// konsulin tier at enrollment.
func runBootstrap(ctx context.Context, env *Env) error {
	ab := adminboot.New(env.BaseURL, env.client())
	bearer, err := ab.Login(ctx, env.AdminUser, env.AdminPass)
	if err != nil {
		return named("bootstrap: login", err)
	}
	endpoints := map[string]string{"health": env.partyHealthURL()}
	if callbacks := env.callbackURL(); callbacks != "" {
		endpoints["callbacks"] = callbacks
	}
	partyID, err := ab.CreateParty(ctx, bearer, adminboot.CreatePartyRequest{
		OrgName:       "QC Chain Conformance Party",
		OrgIdentifier: "qc-chain-conformance",
		Tier:          "authorized",
		Endpoints:     endpoints,
	})
	if err != nil {
		return named("bootstrap: create party", err)
	}
	token, err := ab.IssueEnrollmentToken(ctx, bearer, partyID)
	if err != nil {
		return named("bootstrap: issue enrollment token", err)
	}
	env.PartyID = partyID
	env.EnrollmentToken = token
	return nil
}

// runEnrollment registers a fresh Ed25519 key with the bootstrap
// enrollment token, threads it into env.Priv as the chain signer, and
// promotes the enrolled party to the konsulin tier over a fresh
// adminboot login — the promotion follows a successful enroll.
func runEnrollment(ctx context.Context, env *Env) error {
	if env.PartyID == "" || env.EnrollmentToken == "" {
		return errors.New("conformance: enrollment: run bootstrap first")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return named("enrollment: generate key", err)
	}
	pc, err := partiesClient(env, "enrollment")
	if err != nil {
		return err
	}
	out, err := pc.Enroll(ctx, parties.EnrollInput{PartyID: env.PartyID, EnrollmentToken: env.EnrollmentToken}, priv)
	if err != nil {
		return named("enrollment", err)
	}
	if out.PartyID != env.PartyID {
		return fmt.Errorf("conformance: enrollment: enrolled party %q, want %q", out.PartyID, env.PartyID)
	}
	ab := adminboot.New(env.BaseURL, env.client())
	bearer, err := ab.Login(ctx, env.AdminUser, env.AdminPass)
	if err != nil {
		return named("enrollment: admin login", err)
	}
	tier, err := ab.SetTier(ctx, bearer, env.PartyID, "konsulin")
	if err != nil {
		return named("enrollment: set tier", err)
	}
	if tier != "konsulin" {
		return fmt.Errorf("conformance: enrollment: applied tier %q, want %q", tier, "konsulin")
	}
	env.Priv = priv
	return nil
}

// runRotation installs a fresh key through parties.Rotate, signed by
// the enrolled chain key, and makes it the chain signer.
func runRotation(ctx context.Context, env *Env) error {
	if len(env.Priv) == 0 {
		return errors.New("conformance: rotation: run enrollment first")
	}
	_, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return named("rotation: generate key", err)
	}
	pub, _ := next.Public().(ed25519.PublicKey)
	kid, err := edThumbprint(pub)
	if err != nil {
		return named("rotation", err)
	}
	pc, err := partiesClient(env, "rotation")
	if err != nil {
		return err
	}
	out, err := pc.Rotate(ctx, env.PartyID, wire.RotateKeyRequest{
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Kid:       kid,
		Alg:       "Ed25519",
	})
	if err != nil {
		return named("rotation", err)
	}
	if out.Kid != kid {
		return fmt.Errorf("conformance: rotation: installed kid %q, want %q", out.Kid, kid)
	}
	env.Priv = next
	return nil
}

// runJWKS fetches the party JWKS and requires the rotated key's kid to
// be served.
func runJWKS(ctx context.Context, env *Env) error {
	pc, err := partiesClient(env, "jwks")
	if err != nil {
		return err
	}
	out, err := pc.JWKS(ctx, env.PartyID)
	if err != nil {
		return named("jwks", err)
	}
	if len(out.Keys) == 0 {
		return errors.New("conformance: jwks: party jwks carried no keys")
	}
	if len(env.Priv) == 0 {
		return nil
	}
	pub, _ := env.Priv.Public().(ed25519.PublicKey)
	kid, err := edThumbprint(pub)
	if err != nil {
		return named("jwks", err)
	}
	for _, key := range out.Keys {
		if key.Kid == kid {
			return nil
		}
	}
	return fmt.Errorf("conformance: jwks: rotated kid %q not served", kid)
}

// runIdentities registers, resolves, and links one hashed identity
// over the identities routes.
func runIdentities(ctx context.Context, env *Env) error {
	ic, err := identitiesClient(env, "identities")
	if err != nil {
		return err
	}
	hash := identityHash("conformance-identity@example.test")
	reg, err := ic.Register(ctx, wire.RegisterIdentityRequest{
		ResourceType: "patient", LocalResourceID: "conformance-patient-001", EmailHash: hash, PhoneHash: "N/A",
	})
	if err != nil {
		return named("identities: register", err)
	}
	if reg.GlobalKey == "" {
		return errors.New("conformance: identities: register returned no global key")
	}
	if _, err := ic.Resolve(ctx, wire.ResolveIdentityRequest{EmailHash: hash, PhoneHash: "N/A"}); err != nil {
		return named("identities: resolve", err)
	}
	link, err := ic.Link(ctx, wire.LinkIdentityRequest{GlobalKey: reg.GlobalKey, LocalResourceID: "conformance-patient-002"})
	if err != nil {
		return named("identities: link", err)
	}
	if !link.Linked {
		return errors.New("conformance: identities: link was not applied")
	}
	return nil
}

// runApprovals mints one referral approval ticket and requires the
// ticket to come back non-empty.
func runApprovals(ctx context.Context, env *Env) error {
	ac, err := approvalsClient(env, "approvals")
	if err != nil {
		return err
	}
	out, err := ac.Mint(ctx, wire.MintApprovalRequest{To: env.PartyID, Scope: "referral", Purpose: "conformance referral", TTL: 300})
	if err != nil {
		return named("approvals: mint", err)
	}
	if out.AccessToken == "" {
		return errors.New("conformance: approvals: mint returned no ticket")
	}
	return nil
}

// runListings creates the free listing the payment step purchases,
// lists the marketplace, and threads the listing id into env.
func runListings(ctx context.Context, env *Env) error {
	lc, err := listingsClient(env, "listings")
	if err != nil {
		return err
	}
	created, err := lc.Create(ctx, wire.CreateListingRequest{
		Name: "conformance-free-listing", EndpointURL: env.BaseURL, Price: 0, Invocation: "commodity",
	})
	if err != nil {
		return named("listings: create", err)
	}
	if created.ListingID == "" {
		return errors.New("conformance: listings: create returned no listing id")
	}
	rows, err := lc.List(ctx)
	if err != nil {
		return named("listings: list", err)
	}
	for _, row := range rows.Listings {
		if row.ListingID == created.ListingID {
			env.ListingID = created.ListingID
			return nil
		}
	}
	return fmt.Errorf("conformance: listings: created listing %q not in the marketplace read", created.ListingID)
}

// runPaymentPaid purchases the free listing and requires the payment
// to settle PAID immediately, on create and on the reconciliation read.
func runPaymentPaid(ctx context.Context, env *Env) error {
	if env.ListingID == "" {
		return errors.New("conformance: payment-paid: run listings first")
	}
	pay, err := paymentsClient(env, "payment-paid")
	if err != nil {
		return err
	}
	out, err := pay.Create(ctx, wire.CreatePaymentRequest{ListingID: env.ListingID})
	if err != nil {
		return named("payment-paid: create", err)
	}
	if out.Status != "PAID" {
		return fmt.Errorf("conformance: payment-paid: status %q, want PAID", out.Status)
	}
	got, err := pay.Get(ctx, out.PaymentID)
	if err != nil {
		return named("payment-paid: get", err)
	}
	if got.Status != "PAID" {
		return fmt.Errorf("conformance: payment-paid: reconciliation status %q, want PAID", got.Status)
	}
	return nil
}

// runWebhooks enqueues one invocation of the chain party's own
// listing, then reads its delivery state.
func runWebhooks(ctx context.Context, env *Env) error {
	wh, err := webhooksClient(env, "webhooks")
	if err != nil {
		return err
	}
	enq, err := wh.Enqueue(ctx, wire.EnqueueWebhookRequest{
		To: env.PartyID, Service: "conformance-free-listing", Payload: json.RawMessage(`{"conformance":"qc-chain"}`),
	})
	if err != nil {
		return named("webhooks: enqueue", err)
	}
	if enq.WebhookID == "" {
		return errors.New("conformance: webhooks: enqueue returned no webhook id")
	}
	status, err := wh.Status(ctx, enq.WebhookID)
	if err != nil {
		return named("webhooks: status", err)
	}
	if status.State == "" {
		return errors.New("conformance: webhooks: status returned no state")
	}
	return nil
}
