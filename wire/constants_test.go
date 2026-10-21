package wire_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// TestTypConstants asserts each of the six typ strings literally against
// PRD §9.7 / the gateway Token Kinds table (SDK-WIRE-002). Any drift in
// a constant fails here because expected values are written out, not
// derived from the package under test.
func TestTypConstants(t *testing.T) {
	assert.Equal(t, "ks-party+jwt", wire.TypParty)
	assert.Equal(t, "ks-approval+jwt", wire.TypApproval)
	assert.Equal(t, "ks-access+jwt", wire.TypAccess)
	assert.Equal(t, "ks-delivery+jwt", wire.TypDelivery)
	assert.Equal(t, "ks-event+jwt", wire.TypEvent)
	assert.Equal(t, "ks-result+jwt", wire.TypResult)
}

// TestTypsList asserts the exported typ list in Token Kinds table order.
func TestTypsList(t *testing.T) {
	want := []string{
		"ks-party+jwt",
		"ks-approval+jwt",
		"ks-access+jwt",
		"ks-delivery+jwt",
		"ks-event+jwt",
		"ks-result+jwt",
	}
	assert.Equal(t, want, wire.Typs())
}

// TestPurposeConstants asserts the five token purposes literally
// (PRD §9.7: webhook-delivery, settlement-notification, service-result,
// webhook-result, admin-auth).
func TestPurposeConstants(t *testing.T) {
	assert.Equal(t, "webhook-delivery", wire.PurposeWebhookDelivery)
	assert.Equal(t, "settlement-notification", wire.PurposeSettlementNotification)
	assert.Equal(t, "service-result", wire.PurposeServiceResult)
	assert.Equal(t, "webhook-result", wire.PurposeWebhookResult)
	assert.Equal(t, "admin-auth", wire.PurposeAdminAuth)

	want := []string{
		"webhook-delivery",
		"settlement-notification",
		"service-result",
		"webhook-result",
		"admin-auth",
	}
	assert.Equal(t, want, wire.Purposes())
}

// TestCapabilityCatalog asserts every capability id literally in PRD §9.7
// order, including the two study-scoped templates.
func TestCapabilityCatalog(t *testing.T) {
	assert.Equal(t, "approval:referral", wire.CapabilityApprovalReferral)
	assert.Equal(t, "approval:export:<study>", wire.CapabilityApprovalExportStudy)
	assert.Equal(t, "listing:enlist", wire.CapabilityListingEnlist)
	assert.Equal(t, "webhook:invoke", wire.CapabilityWebhookInvoke)
	assert.Equal(t, "payment:create", wire.CapabilityPaymentCreate)
	assert.Equal(t, "identity:register", wire.CapabilityIdentityRegister)
	assert.Equal(t, "identity:resolve", wire.CapabilityIdentityResolve)
	assert.Equal(t, "identity:link", wire.CapabilityIdentityLink)
	assert.Equal(t, "accept:referral", wire.CapabilityAcceptReferral)
	assert.Equal(t, "accept:export:<study>", wire.CapabilityAcceptExportStudy)

	want := []string{
		"approval:referral",
		"approval:export:<study>",
		"listing:enlist",
		"webhook:invoke",
		"payment:create",
		"identity:register",
		"identity:resolve",
		"identity:link",
		"accept:referral",
		"accept:export:<study>",
	}
	assert.Equal(t, want, wire.CapabilityCatalog())
}

// TestTokenKindTable asserts each row of the normative Token Kinds table
// (gateway docs/api/AGENTS.md): typ, signer, required claims, verifier.
func TestTokenKindTable(t *testing.T) {
	table := wire.TokenKindTable()
	require.Len(t, table, 6)

	want := []wire.TokenKind{
		{
			Typ:      "ks-party+jwt",
			Signer:   wire.SignerParty,
			Claims:   []string{"iss", "aud", "iat", "exp", "jti"},
			Verifier: "gateway",
		},
		{
			Typ:      "ks-approval+jwt",
			Signer:   wire.SignerGateway,
			Claims:   []string{"iss", "aud", "sub", "scope", "purpose", "researcher_hash", "jti", "iat", "exp"},
			Verifier: "recipient party",
		},
		{
			Typ:      "ks-access+jwt",
			Signer:   wire.SignerGateway,
			Claims:   []string{"iss", "aud", "sub", "scope", "purpose", "jti", "iat", "exp"},
			Verifier: "provider",
		},
		{
			Typ:      "ks-delivery+jwt",
			Signer:   wire.SignerGateway,
			Claims:   []string{"iss", "aud", "sub", "purpose", "webhook_id", "user_ref", "body_sha256", "iat", "exp"},
			Verifier: "recipient endpoint",
		},
		{
			Typ:      "ks-event+jwt",
			Signer:   wire.SignerGateway,
			Claims:   []string{"iss", "aud", "sub", "purpose", "webhook_id", "body_sha256", "iat", "exp"},
			Verifier: "party callbacks",
		},
		{
			Typ:      "ks-result+jwt",
			Signer:   wire.SignerGateway,
			Claims:   []string{"iss", "aud", "sub", "purpose", "jti", "webhook_id", "iat", "exp"},
			Verifier: "gateway",
		},
	}
	assert.Equal(t, want, table)
}

// TestTokenKindTableMatchesTyps cross-checks the table's typ column
// against the exported typ list so the two cannot drift apart.
func TestTokenKindTableMatchesTyps(t *testing.T) {
	table := wire.TokenKindTable()
	typs := make([]string, 0, len(table))
	for _, row := range table {
		typs = append(typs, row.Typ)
	}
	assert.Equal(t, wire.Typs(), typs)
}

// TestKindForTyp looks each kind up by its typ and checks the miss case.
func TestKindForTyp(t *testing.T) {
	row, ok := wire.KindForTyp("ks-delivery+jwt")
	require.True(t, ok)
	assert.Equal(t, wire.SignerGateway, row.Signer)

	_, ok = wire.KindForTyp("JWT")
	assert.False(t, ok)
}
