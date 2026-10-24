package wire

// Typ constants — the six token kinds (PRD §9.7 SDK-WIRE-002; gateway
// Token Kinds table). Matching is exact string equality: a missing or
// generic typ fails even under a valid signature (RFC 8725 §3.11).
const (
	// TypParty is the typ of outbound party requests to the gateway.
	TypParty = "ks-party+jwt"
	// TypApproval is the typ of approval handoff tickets.
	TypApproval = "ks-approval+jwt"
	// TypAccess is the typ of payment access tickets.
	TypAccess = "ks-access+jwt"
	// TypDelivery is the typ of webhook invocation delivery tokens.
	TypDelivery = "ks-delivery+jwt"
	// TypEvent is the typ of gateway-origin event delivery tokens
	// (settlement notifications, service results, payment-required
	// notices, service receipts).
	TypEvent = "ks-event+jwt"
	// TypResult is the typ of webhook result submission tickets.
	TypResult = "ks-result+jwt"
)

// Token purpose claim values (PRD §9.7 SDK-WIRE-002).
const (
	// PurposeWebhookDelivery is the purpose on ks-delivery+jwt tokens.
	PurposeWebhookDelivery = "webhook-delivery"
	// PurposeSettlementNotification is the purpose on settlement
	// notification ks-event+jwt tokens.
	PurposeSettlementNotification = "settlement-notification"
	// PurposeServiceResult is the purpose on service-result ks-event+jwt
	// tokens.
	PurposeServiceResult = "service-result"
	// PurposePaymentRequired is the purpose on payment-required
	// ks-event+jwt tokens (gateway hardening: buyer is told a payment
	// is required for a listing).
	PurposePaymentRequired = "payment-required"
	// PurposeServiceReceipt is the purpose on service-receipt
	// ks-event+jwt tokens (gateway hardening: provider-metered 2xx
	// delivered to the buyer).
	PurposeServiceReceipt = "service-receipt"
	// PurposeWebhookResult is the purpose on ks-result+jwt tokens.
	PurposeWebhookResult = "webhook-result"
	// PurposeAdminAuth is the purpose on operator admin-auth tokens
	// (gateway-internal; never minted by the SDK).
	PurposeAdminAuth = "admin-auth"
)

// Capability catalog ids (PRD §9.7 SDK-WIRE-002). The two study-scoped
// ids are templates: "<study>" is replaced by the study slug, which
// matches [a-z0-9._-]{1,64} at the gateway.
const (
	// CapabilityApprovalReferral lets the party mint referral approvals.
	CapabilityApprovalReferral = "approval:referral"
	// CapabilityApprovalExportStudy is the study-scoped export approval
	// capability template.
	CapabilityApprovalExportStudy = "approval:export:<study>"
	// CapabilityListingEnlist lets the party enlist listings.
	CapabilityListingEnlist = "listing:enlist"
	// CapabilityWebhookInvoke lets the party enqueue webhook invocations.
	CapabilityWebhookInvoke = "webhook:invoke"
	// CapabilityPaymentCreate lets the party create payments.
	CapabilityPaymentCreate = "payment:create"
	// CapabilityIdentityRegister lets the party register identities.
	CapabilityIdentityRegister = "identity:register"
	// CapabilityIdentityResolve lets the party resolve identities.
	CapabilityIdentityResolve = "identity:resolve"
	// CapabilityIdentityLink lets the party link identities.
	CapabilityIdentityLink = "identity:link"
	// CapabilityAcceptReferral lets the party receive referral approvals.
	CapabilityAcceptReferral = "accept:referral"
	// CapabilityAcceptExportStudy is the study-scoped inbound export
	// capability template.
	CapabilityAcceptExportStudy = "accept:export:<study>"
)

// Signer identifies who signs a token kind: the party's own key or the
// gateway's signing key.
type Signer string

const (
	// SignerParty marks kinds signed by the party's registered key
	// (header kid resolves the key).
	SignerParty Signer = "party"
	// SignerGateway marks kinds signed by the gateway signing key.
	SignerGateway Signer = "gateway"
)

// TokenKind is one row of the normative Token Kinds table: the exact
// typ, who signs it, the claims the row requires unconditionally, the
// claims the row allows only conditionally, and who verifies it.
type TokenKind struct {
	// Typ is the exact typ header value of the kind.
	Typ string
	// Signer is who signs tokens of this kind.
	Signer Signer
	// Claims lists the claim names the row requires unconditionally.
	Claims []string
	// Conditional lists claim names the row permits only in specific
	// circumstances (e.g. user_ref on user-scoped listings, payment_id
	// when the buyer has a PAID payment for the listing). A missing
	// conditional claim does not fail verification.
	Conditional []string
	// Verifier names the party/endpoint that verifies the kind.
	Verifier string
}

// Typs returns the six typ values in Token Kinds table order. The
// returned slice is a fresh copy; mutating it does not affect the
// package.
func Typs() []string {
	return []string{TypParty, TypApproval, TypAccess, TypDelivery, TypEvent, TypResult}
}

// Purposes returns the seven token purpose values in PRD §9.7 order:
// the five original purposes with the two hardening-era event purposes
// (payment-required, service-receipt) inserted after service-result.
// The returned slice is a fresh copy; mutating it does not affect the
// package.
func Purposes() []string {
	return []string{
		PurposeWebhookDelivery,
		PurposeSettlementNotification,
		PurposeServiceResult,
		PurposePaymentRequired,
		PurposeServiceReceipt,
		PurposeWebhookResult,
		PurposeAdminAuth,
	}
}

// CapabilityCatalog returns the ten capability ids in PRD §9.7 order,
// including the two study-scoped templates. The returned slice is a
// fresh copy; mutating it does not affect the package.
func CapabilityCatalog() []string {
	return []string{
		CapabilityApprovalReferral,
		CapabilityApprovalExportStudy,
		CapabilityListingEnlist,
		CapabilityWebhookInvoke,
		CapabilityPaymentCreate,
		CapabilityIdentityRegister,
		CapabilityIdentityResolve,
		CapabilityIdentityLink,
		CapabilityAcceptReferral,
		CapabilityAcceptExportStudy,
	}
}

// tokenKinds is the normative Token Kinds table, in table order.
var tokenKinds = []TokenKind{
	{
		Typ:      TypParty,
		Signer:   SignerParty,
		Claims:   []string{"iss", "aud", "iat", "exp", "jti"},
		Verifier: "gateway",
	},
	{
		Typ:      TypApproval,
		Signer:   SignerGateway,
		Claims:   []string{"iss", "aud", "sub", "scope", "purpose", "researcher_hash", "jti", "iat", "exp"},
		Verifier: "recipient party",
	},
	{
		Typ:      TypAccess,
		Signer:   SignerGateway,
		Claims:   []string{"iss", "aud", "sub", "scope", "purpose", "jti", "iat", "exp"},
		Verifier: "provider",
	},
	{
		Typ:         TypDelivery,
		Signer:      SignerGateway,
		Claims:      []string{"iss", "aud", "sub", "purpose", "webhook_id", "body_sha256", "iat", "exp"},
		Conditional: []string{"user_ref", "payment_id"},
		Verifier:    "recipient endpoint",
	},
	{
		Typ:      TypEvent,
		Signer:   SignerGateway,
		Claims:   []string{"iss", "aud", "sub", "purpose", "webhook_id", "body_sha256", "iat", "exp"},
		Verifier: "party callbacks",
	},
	{
		Typ:      TypResult,
		Signer:   SignerGateway,
		Claims:   []string{"iss", "aud", "sub", "purpose", "jti", "webhook_id", "iat", "exp"},
		Verifier: "gateway",
	},
}

// TokenKindTable returns the normative Token Kinds table (six rows, in
// table order). The returned slice and its Claims and Conditional
// contents are fresh copies; mutating them does not affect the
// package.
func TokenKindTable() []TokenKind {
	out := make([]TokenKind, len(tokenKinds))
	for i, row := range tokenKinds {
		out[i] = row
		out[i].Claims = append([]string(nil), row.Claims...)
		out[i].Conditional = append([]string(nil), row.Conditional...)
	}
	return out
}

// KindForTyp looks one token kind up by its exact typ header value.
// Returns a deep copy of the table row and true on a hit, and false for
// any other value — callers must fail closed on a miss (RFC 8725
// §3.11).
func KindForTyp(typ string) (TokenKind, bool) {
	for _, row := range tokenKinds {
		if row.Typ == typ {
			return TokenKind{
				Typ:         row.Typ,
				Signer:      row.Signer,
				Claims:      append([]string(nil), row.Claims...),
				Conditional: append([]string(nil), row.Conditional...),
				Verifier:    row.Verifier,
			}, true
		}
	}
	return TokenKind{}, false
}
