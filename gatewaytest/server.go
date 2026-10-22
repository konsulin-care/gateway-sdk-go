package gatewaytest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
)

// jwksContentType is the media type of a JWKS document served over HTTP
// (RFC 8053 section 3).
const jwksContentType = "application/jwk-set+json"

// JWKSServer is a fake gateway JWKS endpoint: a local httptest server that
// serves a fixed JWKS document and verifies compact tokens against that
// document using kid-only key selection, mirroring the gateway's key
// resolution rules offline. Its Verify path is EdDSA-only, matching the
// gateway tokens the SDK accepts.
type JWKSServer struct {
	server *httptest.Server
	jwks   []byte
	keys   jwk.KeySet
}

// NewJWKSServer validates jwks (fail-closed via jwk.ParseJWKS) and starts a
// local httptest server that serves exactly those bytes at URL(). No server
// is started when the document does not parse.
//
// Parameters: jwks is the raw JWKS document to serve — the mirrored
// testdata/golden/gateway-jwks.json or a document built around a test key
// with Ed25519JWKS.
// Returns: the running fake server and nil, or an error naming the parse
// failure. Zero network beyond the local loopback listener.
func NewJWKSServer(jwks []byte) (*JWKSServer, error) {
	keys, err := jwk.ParseJWKS(jwks)
	if err != nil {
		return nil, fmt.Errorf("gatewaytest: fake JWKS: %w", err)
	}
	s := &JWKSServer{
		jwks: append([]byte(nil), jwks...),
		keys: keys,
	}
	s.server = httptest.NewServer(http.HandlerFunc(s.handleJWKS))
	return s, nil
}

// Ed25519JWKS builds the JWKS document for one Ed25519 public key: a single
// OKP/Ed25519 sig key whose kid is the key's RFC 7638 thumbprint. The
// returned document parses with the jwk package (verified before return).
//
// Parameters: pub is the Ed25519 public key (32 bytes).
// Returns: the JWKS document and nil, or an error for a wrong-size key or a
// document that does not validate. Never panics.
func Ed25519JWKS(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("gatewaytest: JWKS: public key is %d bytes, want %d",
			len(pub), ed25519.PublicKeySize)
	}
	key := map[string]string{
		"alg": "EdDSA",
		"crv": "Ed25519",
		"kty": "OKP",
		"use": "sig",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
	rawKey, err := json.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("gatewaytest: JWKS: key: %w", err)
	}
	kid, err := jwk.Thumbprint(rawKey)
	if err != nil {
		return nil, fmt.Errorf("gatewaytest: JWKS: kid: %w", err)
	}
	key["kid"] = kid
	doc, err := json.Marshal(map[string]any{"keys": []map[string]string{key}})
	if err != nil {
		return nil, fmt.Errorf("gatewaytest: JWKS: document: %w", err)
	}
	if _, err := jwk.ParseJWKS(doc); err != nil {
		return nil, fmt.Errorf("gatewaytest: JWKS: built document does not validate: %w", err)
	}
	return doc, nil
}

// URL returns the JWKS endpoint URL of the fake server (for http.Get in
// tests). It must only be called on a server returned by NewJWKSServer.
func (s *JWKSServer) URL() string {
	return s.server.URL
}

// JWKS returns a copy of the served JWKS document — the exact bytes the
// handler writes on every GET.
func (s *JWKSServer) JWKS() []byte {
	return append([]byte(nil), s.jwks...)
}

// Close shuts the fake server down. It is safe to call more than once and
// is intended for t.Cleanup.
func (s *JWKSServer) Close() {
	s.server.Close()
}

// Verify checks one compact token against the served JWKS with kid-only key
// selection: the kid comes from the token's own protected header (never a
// caller hint), the key must be present in the served document — an unknown
// kid denies before any signature check — the selected key must be
// OKP/Ed25519, and the EdDSA signature must verify over the token's exact
// signing input.
//
// This is the fake's EdDSA verify path for tests; typ/claim policy belongs
// to the real verify package (out of scope for the test kit).
//
// Parameters: token is the compact JWS to verify.
// Returns: the verified payload and nil, or an error naming the denial
// reason (parse failure, unknown kid, non-Ed25519 key, bad signature).
// Fail closed; never panics.
func (s *JWKSServer) Verify(token string) ([]byte, error) {
	hdr, _, _, err := jws.Parse([]byte(token))
	if err != nil {
		return nil, fmt.Errorf("gatewaytest: verify: %w", err)
	}
	key, ok := s.keys.ByKid(hdr.Kid)
	if !ok {
		return nil, fmt.Errorf("gatewaytest: verify: unknown kid %q", hdr.Kid)
	}
	pub, err := ed25519PublicKey(key)
	if err != nil {
		return nil, err
	}
	_, payload, err := jws.VerifyEd25519(pub, []byte(token))
	if err != nil {
		return nil, fmt.Errorf("gatewaytest: verify: %w", err)
	}
	return payload, nil
}

// handleJWKS serves the fixed document at the server's root path.
func (s *JWKSServer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", jwksContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.jwks)
}

// ed25519PublicKey decodes a selected OKP/Ed25519 JWK to its raw public key.
// Any other key type denies: the fake verify path is EdDSA-only, matching
// the gateway token rules (ES256 never appears on this path).
func ed25519PublicKey(key jwk.Key) (ed25519.PublicKey, error) {
	if key.Kty != "OKP" || key.Crv != "Ed25519" {
		return nil, fmt.Errorf("gatewaytest: verify: kid %q: key type %s/%s is not Ed25519",
			key.Kid, key.Kty, key.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("gatewaytest: verify: kid %q: key x: %w", key.Kid, err)
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("gatewaytest: verify: kid %q: key x is %d bytes, want %d",
			key.Kid, len(x), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(x), nil
}
