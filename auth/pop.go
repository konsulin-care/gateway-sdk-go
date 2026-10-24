package auth

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// gatewayAudience is the only audience an enrollment proof carries
// (gateway registry enrollAudience).
const gatewayAudience = "gateway"

// Stored key-row algorithm values the gateway accepts in the enrollment
// body alg field (gateway registry normalizeKeyAlg: Ed25519 or ES256).
const (
	bodyAlgEd25519 = "Ed25519"
	bodyAlgES256   = "ES256"
)

// EnrollmentClaims are the claims of an enrollment proof of possession
// (SDK-AUTH-002): the ks-party+jwt claim set in its byte-exact order
// (aud, exp, iat, iss, jti) plus body_sha256.
type EnrollmentClaims struct {
	PartyClaims
	// BodySHA256 is the unpadded base64url SHA-256 of the exact POST
	// body bytes the proof is bound to.
	BodySHA256 string `json:"body_sha256"`
}

// EnrollmentInput carries the caller-supplied inputs of one enrollment
// attempt (SDK-AUTH-002).
type EnrollmentInput struct {
	// Claims are the proof's ks-party+jwt claims: Iss is the enrolled
	// party id and Aud must be "gateway".
	Claims PartyClaims
	// EnrollmentToken is the single-use enrollment token delivered out
	// of band by the operator.
	EnrollmentToken string
	// EncPublicKey is the optional X25519 encryption key in the
	// registration encoding (base64.StdEncoding, raw 32 bytes). Empty
	// omits the field from the body.
	EncPublicKey string
}

// EnrollmentRequest is one built enrollment attempt: the exact body bytes
// to POST and the proof-of-possession token for the Authorization header.
type EnrollmentRequest struct {
	// Body is the exact JSON body of POST /v1/parties/{id}/enroll. Send
	// these bytes verbatim — the proof's body_sha256 hashes them.
	Body []byte
	// Proof is the ks-party+jwt proof of possession. Send it as
	// "Authorization: Bearer " + Proof; it never travels in the body.
	Proof string
}

// BuildEnrollment builds the exact body bytes and the proof of possession
// for POST /v1/parties/{id}/enroll with the default Ed25519 key
// (SDK-AUTH-002). The body carries enrollment_token, public_key (the
// base64.StdEncoding registration encoding), kid = the RFC 7638
// thumbprint of the submitted public key, alg Ed25519, and the optional
// enc_public_key. The proof is a ks-party+jwt signed by the same key
// (header alg EdDSA, kid = body kid, typ ks-party+jwt) whose body_sha256
// claim is the unpadded base64url SHA-256 of the returned body bytes.
//
// Parameters: in holds the claims, enrollment token, and optional
// encryption key; key is the Ed25519 private key whose public half is
// submitted. Returns: the request to send, or an error. Never panics.
func BuildEnrollment(in EnrollmentInput, key ed25519.PrivateKey) (EnrollmentRequest, error) {
	if len(key) != ed25519.PrivateKeySize {
		return EnrollmentRequest{}, fmt.Errorf("auth: build enrollment: Ed25519 private key is %d bytes, want %d", len(key), ed25519.PrivateKeySize)
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return EnrollmentRequest{}, fmt.Errorf("auth: build enrollment: Ed25519 key exposes public key type %T", key.Public())
	}
	kid, err := ed25519Thumbprint(key)
	if err != nil {
		return EnrollmentRequest{}, fmt.Errorf("auth: build enrollment: %w", err)
	}
	body, hash, err := buildEnrollmentBody(in, bodyAlgEd25519, base64.StdEncoding.EncodeToString(pub), kid)
	if err != nil {
		return EnrollmentRequest{}, err
	}
	hdr := jws.Header{Alg: jws.AlgEdDSA, Kid: kid, Typ: wire.TypParty}
	proof, err := signEnrollmentProof(hdr, in.Claims, hash, func(h jws.Header, p []byte) (string, error) {
		return jws.SignEd25519(key, h, p)
	})
	if err != nil {
		return EnrollmentRequest{}, err
	}
	return EnrollmentRequest{Body: body, Proof: proof}, nil
}

// BuildEnrollmentES256 builds the exact body bytes and the proof of
// possession for POST /v1/parties/{id}/enroll with the explicit opt-in
// ES256 key (SDK-AUTH-002). Identical to BuildEnrollment except the body
// alg is ES256 and the proof header alg is ES256; the default allow-list
// for ks-party+jwt stays EdDSA, so only an explicitly ES256-selecting
// verification path accepts the proof.
//
// Parameters: in holds the claims, enrollment token, and optional
// encryption key; key is the opt-in ES256Key wrapping the P-256 private
// key whose public half is submitted.
// Returns: the request to send, or an error. Never panics.
func BuildEnrollmentES256(in EnrollmentInput, key ES256Key) (EnrollmentRequest, error) {
	if key.Private == nil || key.Private.Curve != elliptic.P256() {
		return EnrollmentRequest{}, errors.New("auth: build enrollment ES256: key must be an EC P-256 private key")
	}
	kid, err := p256Thumbprint(&key.Private.PublicKey)
	if err != nil {
		return EnrollmentRequest{}, fmt.Errorf("auth: build enrollment ES256: %w", err)
	}
	point, err := key.Private.PublicKey.Bytes() // uncompressed 0x04||X||Y; errors, never panics
	if err != nil {
		return EnrollmentRequest{}, fmt.Errorf("auth: build enrollment ES256: public key: %w", err)
	}
	body, hash, err := buildEnrollmentBody(in, bodyAlgES256, base64.StdEncoding.EncodeToString(point), kid)
	if err != nil {
		return EnrollmentRequest{}, err
	}
	hdr := jws.Header{Alg: jws.AlgES256, Kid: kid, Typ: wire.TypParty}
	proof, err := signEnrollmentProof(hdr, in.Claims, hash, func(h jws.Header, p []byte) (string, error) {
		return jws.SignES256(key.Private, h, p)
	})
	if err != nil {
		return EnrollmentRequest{}, err
	}
	return EnrollmentRequest{Body: body, Proof: proof}, nil
}

// enrollmentBody is the JSON body of POST /v1/parties/{id}/enroll
// (gateway delivery http.enrollRequest); enc_public_key is omitted when
// empty.
type enrollmentBody struct {
	EnrollmentToken string `json:"enrollment_token"`
	PublicKey       string `json:"public_key"`
	Kid             string `json:"kid"`
	Alg             string `json:"alg"`
	EncPublicKey    string `json:"enc_public_key,omitempty"`
}

// buildEnrollmentBody validates the shared inputs, marshals the exact
// body bytes, and returns them with the unpadded base64url SHA-256 that
// binds the proof to those bytes.
func buildEnrollmentBody(in EnrollmentInput, bodyAlg, publicKey, kid string) ([]byte, string, error) {
	if err := in.Claims.Validate(); err != nil {
		return nil, "", err
	}
	if in.Claims.Aud != gatewayAudience {
		return nil, "", fmt.Errorf("auth: build enrollment: aud must be %q, got %q", gatewayAudience, in.Claims.Aud)
	}
	if in.EnrollmentToken == "" {
		return nil, "", errors.New("auth: build enrollment: enrollment_token is required")
	}
	raw, err := json.Marshal(enrollmentBody{
		EnrollmentToken: in.EnrollmentToken,
		PublicKey:       publicKey,
		Kid:             kid,
		Alg:             bodyAlg,
		EncPublicKey:    in.EncPublicKey,
	})
	if err != nil {
		return nil, "", fmt.Errorf("auth: build enrollment: body JSON: %w", err)
	}
	sum := sha256.Sum256(raw)
	return raw, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// signEnrollmentProof signs the ks-party+jwt proof claims (the party
// claims plus body_sha256) with the caller-supplied signing closure — the
// Ed25519 default or the explicit ES256 opt-in.
func signEnrollmentProof(hdr jws.Header, claims PartyClaims, bodySHA256 string, sign func(jws.Header, []byte) (string, error)) (string, error) {
	payload, err := json.Marshal(EnrollmentClaims{PartyClaims: claims, BodySHA256: bodySHA256})
	if err != nil {
		return "", fmt.Errorf("auth: build enrollment: proof claims JSON: %w", err)
	}
	tok, err := sign(hdr, payload)
	if err != nil {
		return "", fmt.Errorf("auth: build enrollment: proof: %w", err)
	}
	return tok, nil
}
