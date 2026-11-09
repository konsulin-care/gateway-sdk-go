package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// algECDHES is the envelope key-agreement algorithm: ECDH-ES direct
	// key agreement (RFC 7518 section 4.6).
	algECDHES = "ECDH-ES"
	// encA256GCM is the envelope content-encryption algorithm (RFC 7518
	// section 5.1).
	encA256GCM = "A256GCM"
	// ivBytes is the GCM nonce length in bytes.
	ivBytes = 12
	// tagBytes is the GCM authentication tag length in bytes.
	tagBytes = 16
)

// epkHeader is the sender's ephemeral public key as published in the
// protected header (an OKP/X25519 JWK public component).
type epkHeader struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// protectedHeader is the compact-JWE protected header of the envelope:
// the normative alg/enc/kid members plus the sender's ephemeral epk.
type protectedHeader struct {
	Alg string    `json:"alg"`
	Enc string    `json:"enc"`
	Kid string    `json:"kid"`
	Epk epkHeader `json:"epk"`
}

// Seal seals payload to the recipient's X25519 public key and returns the
// compact JWE (RFC 7516 section 7.1) per the gateway's normative JWE
// Envelope: alg ECDH-ES (direct key agreement), enc A256GCM, a fresh
// ephemeral X25519 key per message published as epk in the protected
// header, kid carried verbatim, an empty encrypted-key segment, the
// Concat KDF (SHA-256, AlgorithmID "A256GCM", empty apu/apv, keydatalen
// 256) deriving the content-encryption key, a 12-byte IV, a 16-byte tag,
// and the encoded protected header as AAD.
//
// Parameters: payload is the plaintext to protect; kid is the recipient
// key identifier published in the protected header; recipient is the
// recipient's X25519 use:enc public key.
// Returns: the compact JWE string and nil, or an error. Fails closed on a
// nil recipient or an empty kid — no ciphertext ever leaves unprotected.
func Seal(payload []byte, kid string, recipient *ecdh.PublicKey) (string, error) {
	if recipient == nil {
		return "", errors.New("envelope: Seal: recipient public key is nil")
	}
	if kid == "" {
		return "", errors.New("envelope: Seal: kid must not be empty")
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("envelope: Seal: ephemeral X25519 key: %w", err)
	}
	return seal(payload, kid, recipient, ephemeral)
}

// seal is the internal seal with an injected ephemeral key and optional
// randomness source: Seal generates a fresh ephemeral per message and
// draws the IV from crypto/rand, while deterministic vector tests pin
// the epk and the IV randomness so the whole seal becomes reproducible.
//
// Parameters: payload the plaintext; kid the recipient key identifier;
// recipient the recipient's X25519 public key; ephemeral the sender's
// ephemeral X25519 private key; rnd is the IV randomness source — nil or
// omitted means crypto/rand, so public Seal/SealBound output stays byte-
// identical for callers. Never exported: the public path always draws a
// fresh ephemeral.
// Returns: the compact JWE string and nil, or an error.
func seal(payload []byte, kid string, recipient *ecdh.PublicKey, ephemeral *ecdh.PrivateKey, rnd ...io.Reader) (string, error) {
	z, err := ephemeral.ECDH(recipient)
	if err != nil {
		return "", fmt.Errorf("envelope: seal: ECDH agreement: %w", err)
	}
	cek := concatKDF(z, []byte(encA256GCM), nil, nil, cekBits)
	header, err := json.Marshal(protectedHeader{
		Alg: algECDHES,
		Enc: encA256GCM,
		Kid: kid,
		Epk: epkHeader{
			Kty: "OKP",
			Crv: "X25519",
			X:   base64.RawURLEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		},
	})
	if err != nil {
		return "", fmt.Errorf("envelope: seal: protected header: %w", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	gcm, err := newGCM(cek)
	if err != nil {
		return "", err
	}
	// nil (or omitted) randomness means crypto/rand; an injected reader
	// replaces it on the test-only deterministic path.
	ivSource := io.Reader(rand.Reader)
	if len(rnd) > 0 && rnd[0] != nil {
		ivSource = rnd[0]
	}
	iv := make([]byte, ivBytes)
	if _, err := io.ReadFull(ivSource, iv); err != nil {
		return "", fmt.Errorf("envelope: seal: IV randomness: %w", err)
	}
	// AAD is the ASCII bytes of the encoded protected header (RFC 7516
	// section 5.1); the tag covers it, so a tampered header cannot open.
	sealed := gcm.Seal(nil, iv, payload, []byte(encodedHeader))
	ciphertext, tag := sealed[:len(sealed)-tagBytes], sealed[len(sealed)-tagBytes:]
	return strings.Join([]string{
		encodedHeader,
		"", // empty encrypted-key segment: ECDH-ES direct agreement wraps no CEK
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(ciphertext),
		base64.RawURLEncoding.EncodeToString(tag),
	}, "."), nil
}

// newGCM builds the A256GCM content cipher from a 256-bit key.
func newGCM(cek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("envelope: AES-256 block: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: AES-GCM: %w", err)
	}
	return gcm, nil
}
