package envelope

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Decrypter performs the X25519 key agreement needed to open an envelope:
// ECDH between the recipient's private key and the sender's ephemeral
// public key from the protected header. *ecdh.PrivateKey satisfies it;
// key custody stays with the caller.
type Decrypter interface {
	ECDH(*ecdh.PublicKey) ([]byte, error)
}

// Open opens a compact JWE sealed by Seal through the caller's Decrypter
// (the recipient's X25519 private key) and returns the plaintext. It fails
// closed before any plaintext is produced: a wrong segment count, a
// non-empty encrypted-key segment, a malformed or wrong alg/enc header, a
// missing kid, a non-X25519 epk, a wrong IV or tag length, or a GCM
// authentication failure all deny with a nil plaintext.
//
// Parameters: compact is the five-segment compact JWE; d is the caller's
// Decrypter whose private key matches the header kid.
// Returns: the plaintext bytes and nil, or an error with nil plaintext.
// Plaintext lives in the returned buffer only — never logged, never
// persisted by the SDK.
func Open(compact string, d Decrypter) ([]byte, error) {
	if d == nil {
		return nil, errors.New("envelope: Open: nil Decrypter")
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("envelope: Open: compact JWE must have 5 segments, got %d", len(parts))
	}
	if parts[1] != "" {
		return nil, errors.New("envelope: Open: encrypted-key segment must be empty (ECDH-ES direct key agreement)")
	}
	header, err := decodeProtectedHeader(parts[0])
	if err != nil {
		return nil, err
	}
	ephPub, err := decodeEpk(header.Epk)
	if err != nil {
		return nil, err
	}
	z, err := d.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("envelope: Open: ECDH agreement: %w", err)
	}
	cek := concatKDF(z, []byte(header.Enc), nil, nil, cekBits)
	gcm, err := newGCM(cek)
	if err != nil {
		return nil, err
	}
	iv, ciphertext, tag, err := decodeSegments(parts[2:], gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	ctAndTag := make([]byte, 0, len(ciphertext)+len(tag))
	ctAndTag = append(ctAndTag, ciphertext...)
	ctAndTag = append(ctAndTag, tag...)
	plaintext, err := gcm.Open(nil, iv, ctAndTag, []byte(parts[0]))
	if err != nil {
		return nil, errors.New("envelope: Open: GCM authentication failed: not the recipient key or altered JWE")
	}
	return plaintext, nil
}

// decodeProtectedHeader decodes and validates the protected header before
// any crypto runs: base64url-decodable JSON carrying alg ECDH-ES, enc
// A256GCM, and a non-empty recipient kid.
func decodeProtectedHeader(encoded string) (protectedHeader, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return protectedHeader{}, fmt.Errorf("envelope: Open: protected header decode: %w", err)
	}
	var header protectedHeader
	if err := json.Unmarshal(raw, &header); err != nil {
		return protectedHeader{}, fmt.Errorf("envelope: Open: protected header parse: %w", err)
	}
	if header.Alg != algECDHES || header.Enc != encA256GCM {
		return protectedHeader{}, fmt.Errorf("envelope: Open: unsupported alg/enc %q/%q", header.Alg, header.Enc)
	}
	if header.Kid == "" {
		return protectedHeader{}, errors.New("envelope: Open: protected header must carry the recipient kid")
	}
	return header, nil
}

// decodeEpk validates the sender's ephemeral key from the header: an
// OKP/X25519 public key whose x is a base64url (unpadded) 32-byte
// coordinate. Anything else rejects fail-closed.
func decodeEpk(epk epkHeader) (*ecdh.PublicKey, error) {
	if epk.Kty != "OKP" || epk.Crv != "X25519" {
		return nil, fmt.Errorf("envelope: Open: epk must be OKP/X25519, got %s/%s", epk.Kty, epk.Crv)
	}
	raw, err := base64.RawURLEncoding.DecodeString(epk.X)
	if err != nil {
		return nil, fmt.Errorf("envelope: Open: epk x decode: %w", err)
	}
	key, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("envelope: Open: epk X25519 key: %w", err)
	}
	return key, nil
}

// decodeSegments base64url-decodes the IV, ciphertext, and tag segments
// and validates their lengths against the content cipher before any
// decryption is attempted.
func decodeSegments(segments []string, nonceSize int) (iv, ciphertext, tag []byte, err error) {
	iv, err = base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("envelope: Open: IV decode: %w", err)
	}
	ciphertext, err = base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("envelope: Open: ciphertext decode: %w", err)
	}
	tag, err = base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("envelope: Open: tag decode: %w", err)
	}
	if len(iv) != nonceSize || len(tag) != tagBytes {
		return nil, nil, nil, fmt.Errorf(
			"envelope: Open: bad IV/tag length: IV %d bytes (want %d), tag %d bytes (want %d)",
			len(iv), nonceSize, len(tag), tagBytes)
	}
	return iv, ciphertext, tag, nil
}
