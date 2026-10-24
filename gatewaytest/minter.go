package gatewaytest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/konsulin-care/gateway-sdk-go/auth"
	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// p256UncompressedLen is the length of an uncompressed P-256 point:
// 0x04 || X || Y with 32-byte coordinates.
const p256UncompressedLen = 65

// Minter mints compact tokens with a freshly generated Ed25519 test key.
// The minter is EdDSA by construction: Mint has no algorithm input, so no
// call can produce an ES256 token. ES256 minting lives in MintES256 behind
// the explicit opt-in key type (never a default anywhere in this SDK).
// The key exists only in memory for tests; nothing is persisted.
type Minter struct {
	priv ed25519.PrivateKey
	kid  string
}

// NewMinter generates a fresh Ed25519 test key from crypto/rand and returns
// a Minter whose kid is the RFC 7638 thumbprint of the public key — the kid
// every token Mint produces carries.
//
// Returns: the minter and nil, or an error from key generation. Never
// panics.
func NewMinter() (*Minter, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gatewaytest: minter: generate key: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("gatewaytest: minter: public key type %T", priv.Public())
	}
	kid, err := ed25519Kid(pub)
	if err != nil {
		return nil, fmt.Errorf("gatewaytest: minter: kid: %w", err)
	}
	return &Minter{priv: priv, kid: kid}, nil
}

// Mint signs payload into a compact token with the minter's Ed25519 key:
// protected header alg EdDSA, kid = the minter key's RFC 7638 thumbprint,
// typ = typ exactly. EdDSA is deterministic (RFC 8032): the same minter and
// the same payload always yield the same token. There is deliberately no
// algorithm parameter — this path can never mint an ES256 token.
//
// Parameters: typ is the exact token kind (one of the wire typ values) and
// must not be empty; payload is the raw JSON claims object.
// Returns: the compact JWS and nil, or an error. Never panics.
func (m *Minter) Mint(typ string, payload []byte) (string, error) {
	if typ == "" {
		return "", errors.New("gatewaytest: mint: typ must not be empty")
	}
	tok, err := jws.SignEd25519(m.priv,
		jws.Header{Alg: jws.AlgEdDSA, Kid: m.kid, Typ: typ}, payload)
	if err != nil {
		return "", fmt.Errorf("gatewaytest: mint: %w", err)
	}
	return tok, nil
}

// PublicKey returns the minter's Ed25519 public key (32 bytes), or nil when
// the Minter was not built by NewMinter.
func (m *Minter) PublicKey() ed25519.PublicKey {
	if len(m.priv) != ed25519.PrivateKeySize {
		return nil
	}
	pub, ok := m.priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil
	}
	return pub
}

// Kid returns the RFC 7638 thumbprint of the minter's public key — the kid
// header of every token Mint produces.
func (m *Minter) Kid() string {
	return m.kid
}

// JWKS returns the minter's public key as a single-key JWKS document
// (kid = thumbprint, alg EdDSA), ready to hand to NewJWKSServer so tests can
// mint a token and verify it against the fake gateway JWKS endpoint.
//
// Returns: the JWKS document and nil, or an error when the minter has no
// usable Ed25519 test key. Never panics.
func (m *Minter) JWKS() ([]byte, error) {
	pub := m.PublicKey()
	if pub == nil {
		return nil, errors.New("gatewaytest: minter: JWKS: minter has no Ed25519 test key (use NewMinter)")
	}
	return Ed25519JWKS(pub)
}

// MintES256 mints an ES256 (ECDSA P-256) ks-party+jwt token — the explicit
// opt-in path and the only way this package produces an ES256 token. Mint
// has no algorithm input and always signs EdDSA, so an ES256 token is not
// reachable without calling this function with an auth.ES256Key wrapping a
// P-256 private key; a zero or non-P-256 key is rejected fail-closed. The
// typ is fixed to ks-party+jwt: ES256 is a party-key algorithm only, and
// every default allow-list denies ES256 (acceptance requires an explicit
// PartyES256 selection at verification).
//
// Parameters: key is the opt-in key type wrapping the P-256 private key;
// payload is the raw JSON claims object.
// Returns: the compact JWS (alg ES256, kid = the P-256 RFC 7638 thumbprint)
// and nil, or an error. Never panics.
func MintES256(key auth.ES256Key, payload []byte) (string, error) {
	if key.Private == nil || key.Private.Curve != elliptic.P256() {
		return "", errors.New("gatewaytest: mint ES256: key must be an EC P-256 key in auth.ES256Key — ES256 minting requires the explicit opt-in")
	}
	kid, err := p256Kid(&key.Private.PublicKey)
	if err != nil {
		return "", fmt.Errorf("gatewaytest: mint ES256: kid: %w", err)
	}
	tok, err := jws.SignES256(key.Private,
		jws.Header{Alg: jws.AlgES256, Kid: kid, Typ: wire.TypParty}, payload)
	if err != nil {
		return "", fmt.Errorf("gatewaytest: mint ES256: %w", err)
	}
	return tok, nil
}

// ed25519Kid returns the RFC 7638 thumbprint of an Ed25519 public key.
func ed25519Kid(pub ed25519.PublicKey) (string, error) {
	key := jwk.Key{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
	return key.Thumbprint()
}

// p256Kid returns the RFC 7638 thumbprint of a P-256 public key.
func p256Kid(pub *ecdsa.PublicKey) (string, error) {
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
