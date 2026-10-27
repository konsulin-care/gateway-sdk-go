package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/parties"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// runEnrollFlow covers the enroll flow of SDK-TEST-002: a generated
// Ed25519 keypair is enrolled through parties.Enroll against the fake
// gateway, the recorded request's kid equals the key's RFC 7638
// thumbprint, and the proof-of-possession body_sha256 claim equals the
// SHA-256 of the exact POST bytes the fake recorded.
//
// Parameters: t is the subtest; fx is the shared fixture.
func runEnrollFlow(t *testing.T, fx *fixture) {
	t.Helper()
	ctx := context.Background()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub, ok := priv.Public().(ed25519.PublicKey)
	require.True(t, ok, "ed25519 private key must expose an ed25519.PublicKey")
	wantKid := rfc7638Thumbprint(t, "OKP", "Ed25519",
		base64.RawURLEncoding.EncodeToString(pub))

	pc, err := parties.New(fx.cli, fx.g.URL())
	require.NoError(t, err)
	before := len(fx.g.Recorded())
	resp, err := pc.Enroll(ctx, parties.EnrollInput{
		PartyID:         testPartyID,
		EnrollmentToken: "enroll-token-offline",
	}, priv)
	require.NoError(t, err, "parties.Enroll must succeed against gatewaytest")
	require.NotNil(t, resp)
	assert.Equal(t, testPartyID, resp.PartyID)

	recs := fx.g.Recorded()[before:]
	require.Len(t, recs, 1, "enroll must send exactly one POST")
	rec := recs[0]
	require.Equal(t, "POST", rec.Method)
	require.Equal(t, "/v1/parties/"+testPartyID+"/enroll", rec.Path)

	// The submitted kid is the RFC 7638 thumbprint of the generated key.
	var body struct {
		EnrollmentToken string `json:"enrollment_token"`
		PublicKey       string `json:"public_key"`
		Kid             string `json:"kid"`
		Alg             string `json:"alg"`
	}
	require.NoError(t, json.Unmarshal(rec.Body, &body))
	assert.Equal(t, wantKid, body.Kid, "kid must equal the RFC 7638 thumbprint")
	assert.Equal(t, base64.StdEncoding.EncodeToString(pub), body.PublicKey)
	assert.Equal(t, "Ed25519", body.Alg)

	// The PoP proof's body_sha256 covers the exact recorded POST bytes.
	sum := sha256.Sum256(rec.Body)
	wantHash := base64.RawURLEncoding.EncodeToString(sum[:])
	hdr, claims := decodeEnrollmentProof(t, rec.Authorization)
	assert.Equal(t, wire.TypParty, hdr.Typ, "the proof must be a ks-party+jwt")
	assert.Equal(t, wantKid, hdr.Kid, "the proof header kid must match the body kid")
	assert.Equal(t, wantHash, claims.BodySHA256,
		"PoP body_sha256 must equal the SHA-256 of the exact POST bytes")
	require.NotEmpty(t, claims.JTI, "the proof must carry a jti")
}

// proofHeader is the protected header of an enrollment proof.
type proofHeader struct {
	Typ string `json:"typ"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

// proofClaims are the claims of an enrollment proof, kept to what the
// flow asserts.
type proofClaims struct {
	BodySHA256 string `json:"body_sha256"`
	JTI        string `json:"jti"`
}

// decodeEnrollmentProof splits "Authorization: Bearer <proof>" into its
// base64url protected header and payload without verifying the
// signature — the recorder surfaces what the test put in the token.
//
// Parameters: t is the test; authorization is the verbatim header value.
// Returns: the decoded header and claims.
func decodeEnrollmentProof(t *testing.T, authorization string) (proofHeader, proofClaims) {
	t.Helper()
	require.True(t, strings.HasPrefix(authorization, "Bearer "),
		"the enrollment proof must travel as a Bearer credential")
	parts := strings.Split(strings.TrimPrefix(authorization, "Bearer "), ".")
	require.Len(t, parts, 3, "the proof must be a compact JWS")
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var hdr proofHeader
	require.NoError(t, json.Unmarshal(hdrRaw, &hdr))
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims proofClaims
	require.NoError(t, json.Unmarshal(payload, &claims))
	return hdr, claims
}
