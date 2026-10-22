package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// p256UncompressedLen is the length of an uncompressed P-256 point:
// 0x04 || X || Y with 32-byte coordinates.
const p256UncompressedLen = 65

// ES256Key is the explicit opt-in key type for ES256 (ECDSA P-256) party
// signing. ES256 is never a default anywhere in the SDK: a ks-party+jwt
// token is signed with EdDSA unless the caller wraps its P-256 key in this
// type and calls SignPartyRequestES256.
type ES256Key struct {
	// Private is the EC P-256 private key that signs the token.
	Private *ecdsa.PrivateKey
}

// SignPartyRequest signs claims into a compact ks-party+jwt token
// (SDK-AUTH-001) with the default Ed25519 algorithm (JWS alg EdDSA). The
// protected header carries typ ks-party+jwt, alg EdDSA, and kid = the RFC
// 7638 thumbprint of the public key. Claims are validated first: exp − iat
// must not exceed MaxPartyLifetime.
//
// key must be an ed25519.PrivateKey. Any other crypto.Signer — including an
// *ecdsa.PrivateKey — is rejected fail-closed: ES256 signing happens only
// through the explicit opt-in key type ES256Key via SignPartyRequestES256.
//
// Parameters: key is the signing key; claims are the ks-party+jwt claims.
// Returns: the compact JWS and nil, or an error. Never panics.
func SignPartyRequest(key crypto.Signer, claims PartyClaims) (string, error) {
	if err := claims.Validate(); err != nil {
		return "", err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return "", fmt.Errorf("auth: sign party request: default algorithm is EdDSA (Ed25519), got key type %T — ES256 signing requires the explicit opt-in: ES256Key with SignPartyRequestES256", key)
	}
	kid, err := ed25519Thumbprint(priv)
	if err != nil {
		return "", fmt.Errorf("auth: sign party request: %w", err)
	}
	payload, err := json.Marshal(claims) // byte-exact order: aud, exp, iat, iss, jti
	if err != nil {
		return "", fmt.Errorf("auth: sign party request: claims JSON: %w", err)
	}
	hdr := jws.Header{Alg: jws.AlgEdDSA, Kid: kid, Typ: wire.TypParty}
	tok, err := jws.SignEd25519(priv, hdr, payload)
	if err != nil {
		return "", fmt.Errorf("auth: sign party request: %w", err)
	}
	return tok, nil
}

// SignPartyRequestES256 signs claims into a compact ks-party+jwt token with
// ES256 (ECDSA P-256, RFC 7518 section 3.4). This is the explicit opt-in
// path: the header carries typ ks-party+jwt, alg ES256, and kid = the RFC
// 7638 thumbprint of the P-256 public key. Claims are validated exactly as
// in SignPartyRequest (exp − iat at most MaxPartyLifetime). The default
// allow-list for ks-party+jwt remains EdDSA, so these tokens are accepted
// only by a verification path that explicitly selects ES256.
//
// Parameters: key is the opt-in ES256Key wrapping the P-256 private key;
// claims are the ks-party+jwt claims.
// Returns: the compact JWS and nil, or an error. Never panics.
func SignPartyRequestES256(key ES256Key, claims PartyClaims) (string, error) {
	if err := claims.Validate(); err != nil {
		return "", err
	}
	if key.Private == nil || key.Private.Curve != elliptic.P256() {
		return "", errors.New("auth: sign party request ES256: key must be an EC P-256 private key")
	}
	kid, err := p256Thumbprint(&key.Private.PublicKey)
	if err != nil {
		return "", fmt.Errorf("auth: sign party request ES256: %w", err)
	}
	payload, err := json.Marshal(claims) // byte-exact order: aud, exp, iat, iss, jti
	if err != nil {
		return "", fmt.Errorf("auth: sign party request ES256: claims JSON: %w", err)
	}
	hdr := jws.Header{Alg: jws.AlgES256, Kid: kid, Typ: wire.TypParty}
	tok, err := jws.SignES256(key.Private, hdr, payload)
	if err != nil {
		return "", fmt.Errorf("auth: sign party request ES256: %w", err)
	}
	return tok, nil
}

// ed25519Thumbprint returns the RFC 7638 thumbprint of an Ed25519 private
// key's public half — the header kid of every EdDSA party token.
func ed25519Thumbprint(priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("Ed25519 private key is %d bytes, want %d",
			len(priv), ed25519.PrivateKeySize)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("Ed25519 key exposes public key type %T", priv.Public())
	}
	key := jwk.Key{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
	return key.Thumbprint()
}

// p256Thumbprint returns the RFC 7638 thumbprint of a P-256 public key —
// the header kid of every ES256 party token.
func p256Thumbprint(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil {
		return "", errors.New("P-256 public key is nil")
	}
	b, err := pub.Bytes() // uncompressed 0x04 || X || Y; errors, never panics
	if err != nil {
		return "", fmt.Errorf("P-256 public key: %w", err)
	}
	if len(b) != p256UncompressedLen {
		return "", fmt.Errorf("P-256 public key is %d bytes, want %d", len(b), p256UncompressedLen)
	}
	key := jwk.Key{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(b[1:33]),
		Y:   base64.RawURLEncoding.EncodeToString(b[33:65]),
	}
	return key.Thumbprint()
}
