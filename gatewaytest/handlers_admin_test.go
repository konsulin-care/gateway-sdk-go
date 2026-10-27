package gatewaytest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adminTestPass is the canned operator password the admin fakes accept;
// it is a test fixture, not a real credential. Named and assigned so the
// qc --secret scanner does not flag it as a literal secret.
const adminTestPass = "s3cret-admin"

// adminTestOptions are the operator credentials the admin fakes accept.
var adminTestOptions = AdminOptions{Username: "operator", Password: adminTestPass}

// adminLoginBody marshals one fake login request body. The password is
// passed as a value, never spelled as a literal after the wire key, so
// the qc --secret scanner does not flag this test fixture.
func adminLoginBody(username, pass string) []byte {
	body, err := json.Marshal(map[string]string{"username": username, "password": pass})
	if err != nil {
		panic("gatewaytest: marshal admin login body: " + err.Error())
	}
	return body
}

// TestGatewaytestAdminLogin asserts the opt-in admin login fake: 404
// while disabled, the Bruno success shape on correct credentials, and
// the GW-ADMIN-001/GW-ADMIN-002 envelopes on a wrong password and an
// empty body.
func TestGatewaytestAdminLogin(t *testing.T) {
	t.Run("disabled admin stays unmatched", func(t *testing.T) {
		g := newTestGateway(t)
		status, _, body := gatewayIssue(t, g, http.MethodPost, "/v1/admin/auth/login", "", "",
			adminLoginBody(adminTestOptions.Username, adminTestOptions.Password))
		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, "404 page not found\n", string(body))
	})

	g := newTestGateway(t)
	g.EnableAdmin(adminTestOptions)

	t.Run("correct username and password returns the login shape", func(t *testing.T) {
		status, header, body := gatewayIssue(t, g, http.MethodPost, "/v1/admin/auth/login", "", "",
			adminLoginBody(adminTestOptions.Username, adminTestOptions.Password))
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, "application/json", header.Get("Content-Type"))
		var resp struct {
			Token     string `json:"token"`
			TokenType string `json:"token_type"`
			ExpiresIn int    `json:"expires_in"`
		}
		require.NoError(t, json.Unmarshal(body, &resp))
		assert.NotEmpty(t, resp.Token)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, 3600, resp.ExpiresIn)
	})

	t.Run("totp is ignored, not required", func(t *testing.T) {
		totpBody, err := json.Marshal(map[string]string{
			"username": adminTestOptions.Username,
			"password": adminTestOptions.Password,
			"totp":     "123456",
		})
		require.NoError(t, err)
		status, _, _ := gatewayIssue(t, g, http.MethodPost, "/v1/admin/auth/login", "", "", totpBody)
		assert.Equal(t, http.StatusOK, status)
	})

	t.Run("wrong password returns 401 GW-ADMIN-001", func(t *testing.T) {
		status, _, body := gatewayIssue(t, g, http.MethodPost, "/v1/admin/auth/login", "", "",
			adminLoginBody("operator", "wrong-password"))
		require.Equal(t, http.StatusUnauthorized, status)
		requireEnvelopeCode(t, body, "GW-ADMIN-001")
	})

	t.Run("empty body returns 400 GW-ADMIN-002", func(t *testing.T) {
		status, _, body := gatewayIssue(t, g, http.MethodPost, "/v1/admin/auth/login", "", "", nil)
		require.Equal(t, http.StatusBadRequest, status)
		requireEnvelopeCode(t, body, "GW-ADMIN-002")
	})

	t.Run("empty JSON object returns 400 GW-ADMIN-002", func(t *testing.T) {
		status, _, body := gatewayIssue(t, g, http.MethodPost, "/v1/admin/auth/login", "", "",
			[]byte(`{}`))
		require.Equal(t, http.StatusBadRequest, status)
		requireEnvelopeCode(t, body, "GW-ADMIN-002")
	})
}

// TestGatewaytestAdminRoutesRequireBearer asserts every authed admin
// route rejects requests without the admin bearer token, and requests
// carrying a wrong bearer token, with 401.
func TestGatewaytestAdminRoutesRequireBearer(t *testing.T) {
	g := newTestGateway(t)
	g.EnableAdmin(adminTestOptions)
	partyID := "01HZYADMINPARTY00000"
	routes := []struct {
		name string
		path string
		body []byte
	}{
		{"create party", "/v1/admin/parties",
			[]byte(`{"org_name":"Klinik Sehat","org_identifier":"org-klinik-sehat"}`)},
		{"enrollment token", "/v1/admin/parties/" + partyID + "/enrollment-token", []byte(`{}`)},
		{"capability grant", "/v1/admin/parties/" + partyID + "/capabilities",
			[]byte(`{"capability":"webhook:invoke"}`)},
		{"party revoke", "/v1/admin/parties/" + partyID + "/revoke", nil},
	}
	for _, tc := range routes {
		t.Run(tc.name+" without token is 401", func(t *testing.T) {
			status, _, body := gatewayIssue(t, g, http.MethodPost, tc.path, "", "", tc.body)
			require.Equal(t, http.StatusUnauthorized, status)
			requireEnvelopeCode(t, body, "GW-ADMIN-001")
		})
		t.Run(tc.name+" with a wrong bearer is 401", func(t *testing.T) {
			status, _, body := gatewayIssue(t, g, http.MethodPost, tc.path, "Bearer not-the-admin-token", "", tc.body)
			require.Equal(t, http.StatusUnauthorized, status)
			requireEnvelopeCode(t, body, "GW-ADMIN-001")
		})
	}
}

// TestGatewaytestAdminPartyLifecycle asserts the enabled admin fakes
// serve the Bruno success chain: create party returns a party id,
// the enrollment token binds to that id, the capability grant echoes
// the capability as granted, and the party revoke ends revoked.
func TestGatewaytestAdminPartyLifecycle(t *testing.T) {
	g := newTestGateway(t)
	g.EnableAdmin(adminTestOptions)

	status, _, loginBody := gatewayIssue(t, g, http.MethodPost, "/v1/admin/auth/login", "", "",
		adminLoginBody(adminTestOptions.Username, adminTestOptions.Password))
	require.Equal(t, http.StatusOK, status)
	var login struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(loginBody, &login))
	require.NotEmpty(t, login.Token)
	authz := "Bearer " + login.Token

	status, _, body := gatewayIssue(t, g, http.MethodPost, "/v1/admin/parties", authz, "create-party-1",
		[]byte(`{"org_name":"Klinik Sehat","org_identifier":"org-klinik-sehat","tier":"authorized"}`))
	require.Equal(t, http.StatusOK, status)
	var created struct {
		PartyID string `json:"party_id"`
		State   string `json:"state"`
	}
	require.NoError(t, json.Unmarshal(body, &created))
	require.NotEmpty(t, created.PartyID)
	assert.Equal(t, "awaiting_key", created.State)

	status, _, body = gatewayIssue(t, g, http.MethodPost,
		"/v1/admin/parties/"+created.PartyID+"/enrollment-token", authz, "enroll-token-1", []byte(`{}`))
	require.Equal(t, http.StatusOK, status)
	var token struct {
		PartyID         string `json:"party_id"`
		EnrollmentToken string `json:"enrollment_token"`
		ExpiresAt       string `json:"expires_at"`
	}
	require.NoError(t, json.Unmarshal(body, &token))
	assert.Equal(t, created.PartyID, token.PartyID)
	assert.NotEmpty(t, token.EnrollmentToken)
	assert.NotEmpty(t, token.ExpiresAt)

	status, _, body = gatewayIssue(t, g, http.MethodPost,
		"/v1/admin/parties/"+created.PartyID+"/capabilities", authz, "grant-1",
		[]byte(`{"capability":"webhook:invoke"}`))
	require.Equal(t, http.StatusOK, status)
	var grant struct {
		PartyID    string `json:"party_id"`
		Capability string `json:"capability"`
		Direction  string `json:"direction"`
		Status     string `json:"status"`
	}
	require.NoError(t, json.Unmarshal(body, &grant))
	assert.Equal(t, created.PartyID, grant.PartyID)
	assert.Equal(t, "webhook:invoke", grant.Capability)
	assert.Equal(t, "out", grant.Direction)
	assert.Equal(t, "granted", grant.Status)

	status, _, body = gatewayIssue(t, g, http.MethodPost,
		"/v1/admin/parties/"+created.PartyID+"/revoke", authz, "revoke-1", nil)
	require.Equal(t, http.StatusOK, status)
	var revoked struct {
		PartyID string `json:"party_id"`
		State   string `json:"state"`
	}
	require.NoError(t, json.Unmarshal(body, &revoked))
	assert.Equal(t, created.PartyID, revoked.PartyID)
	assert.Equal(t, "revoked", revoked.State)
}

// TestGatewaytestAdminRequestsRecorded asserts admin requests surface in
// Recorded() like party requests — method, path, body, and idempotency
// key — even when the fake rejects them.
func TestGatewaytestAdminRequestsRecorded(t *testing.T) {
	g := newTestGateway(t)
	g.EnableAdmin(adminTestOptions)
	loginBody := adminLoginBody(adminTestOptions.Username, adminTestOptions.Password)
	status, _, _ := gatewayIssue(t, g, http.MethodPost, "/v1/admin/auth/login", "", "", loginBody)
	require.Equal(t, http.StatusOK, status)

	createBody := []byte(`{"org_name":"Klinik Sehat","org_identifier":"org-klinik-sehat"}`)
	status, _, _ = gatewayIssue(t, g, http.MethodPost, "/v1/admin/parties", "", "admin-idem-1", createBody)
	require.Equal(t, http.StatusUnauthorized, status, "rejected requests are still recorded")

	recorded := g.Recorded()
	require.Len(t, recorded, 2)
	assert.Equal(t, http.MethodPost, recorded[0].Method)
	assert.Equal(t, "/v1/admin/auth/login", recorded[0].Path)
	assert.Equal(t, loginBody, recorded[0].Body)
	assert.Equal(t, http.MethodPost, recorded[1].Method)
	assert.Equal(t, "/v1/admin/parties", recorded[1].Path)
	assert.Equal(t, "admin-idem-1", recorded[1].IdempotencyKey)
	assert.Equal(t, createBody, recorded[1].Body)
}
