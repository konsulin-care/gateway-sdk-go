package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// AlgES256 is the JWS "alg" header value for ECDSA P-256 signatures with
// SHA-256 (RFC 7518 section 3.4). It is never a default: this SDK signs with
// EdDSA unless the caller explicitly selects ES256 for a party key.
const AlgES256 = "ES256"

// PartyAlg selects the signature algorithm of a party key. The zero value
// is PartyEdDSA, so a caller that selects nothing gets the Ed25519 default
// and can never reach ES256 by omission.
type PartyAlg uint8

const (
	// PartyEdDSA selects Ed25519 (JWS alg EdDSA) for a party key — the
	// default selection, matching the zero value of PartyAlg.
	PartyEdDSA PartyAlg = iota
	// PartyES256 opts a party key in to ECDSA P-256 (JWS alg ES256). Only
	// this explicit selection ever reaches an ES256 token.
	PartyES256
)

// SignES256 signs payload into a compact JWS (RFC 7515 section 7.1) with
// alg ES256. hdr.Alg must be AlgES256 — a wrong or empty alg is an error,
// never silently fixed — so this signer is reachable only through an
// explicit ES256 selection. The signature is ECDSA over the SHA-256 of the
// signing input, emitted as the raw R||S concatenation (RFC 7518 section
// 3.4) after a DER conversion. ECDSA is randomized: identical inputs yield
// different tokens.
//
// Parameters: priv is the EC P-256 private key; hdr is the protected header
// (Alg must be AlgES256; kid/typ optional); payload is the raw JSON payload.
// Returns: the compact JWS and nil, or an error. Never panics.
func SignES256(priv *ecdsa.PrivateKey, hdr Header, payload []byte) (string, error) {
	if hdr.Alg != AlgES256 {
		return "", fmt.Errorf("jws: sign ES256: alg must be %q, got %q", AlgES256, hdr.Alg)
	}
	if priv == nil || priv.Curve != elliptic.P256() {
		return "", errors.New("jws: sign ES256: private key must be an EC P-256 key")
	}
	protected, err := json.Marshal(hdr) // field order: alg, kid, typ — byte-exact
	if err != nil {
		return "", fmt.Errorf("jws: sign ES256: protected header: %w", err)
	}
	input := base64.RawURLEncoding.EncodeToString(protected) +
		"." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("jws: sign ES256: %w", err)
	}
	raw, err := DERToRawSignature(der)
	if err != nil {
		return "", fmt.Errorf("jws: sign ES256: %w", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(raw), nil
}

// VerifyES256 verifies the ES256 signature of a compact JWS and its alg
// header: the protected header must parse (see Parse), state alg ES256
// exactly, and the signature must be exactly 64 raw R||S bytes (RFC 7518
// section 3.4) verifying under SHA-256 over the token's exact signing input.
// A DER-length or otherwise malformed signature segment is denied.
//
// This is the signature layer only: callers MUST additionally run
// CheckKindParty with the expected typ and an explicit PartyES256 selection
// before accepting the token.
//
// Parameters: pub is the EC P-256 public key the caller resolved from the
// token's kid; compact is the token.
// Returns: the protected header, payload bytes, and nil; or an error. Any
// failure denies (fail closed); never panics.
func VerifyES256(pub *ecdsa.PublicKey, compact []byte) (Header, []byte, error) {
	// ecdsa.Verify panics on a key with nil coordinates, so validate first.
	//nolint:staticcheck // SA1019: reading X/Y is the only nil-safe way to reject a malformed caller-supplied key before the stdlib panics.
	if pub == nil || pub.Curve != elliptic.P256() || pub.X == nil || pub.Y == nil {
		return Header{}, nil, errors.New("jws: verify ES256: public key must be an EC P-256 key")
	}
	hdr, signingInput, payload, sig, err := parseCompact(compact)
	if err != nil {
		return Header{}, nil, err
	}
	if hdr.Alg != AlgES256 {
		return Header{}, nil, fmt.Errorf("jws: verify ES256: alg %q is not allowed", hdr.Alg)
	}
	if len(sig) != 2*32 {
		return Header{}, nil, fmt.Errorf("jws: verify ES256: signature is %d bytes, want 64", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256(signingInput)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return Header{}, nil, errors.New("jws: verify ES256: signature verification failed")
	}
	return hdr, payload, nil
}

// CheckKindParty checks a parsed protected header for the ks-party+jwt
// token kind under an explicit algorithm selection. The typ must be
// ks-party+jwt for either selection (the opt-in widens the algorithm, never
// the token kind). PartyEdDSA delegates to CheckKind, which applies the
// default allow-list (EdDSA only, so an ES256 header is denied). PartyES256
// accepts only alg ES256. Any other selection value fails closed.
//
// Parameters: hdr is the header returned by VerifyEd25519 or VerifyES256;
// wantTyp is the typ row the caller is applying (must be ks-party+jwt);
// sel is the explicit algorithm selection for the party key.
// Returns: nil when the header satisfies the row, or an error naming the
// mismatch. Never panics.
func CheckKindParty(hdr Header, wantTyp string, sel PartyAlg) error {
	if wantTyp != typParty {
		return fmt.Errorf("jws: party key tokens must have typ %q, got %q", typParty, wantTyp)
	}
	if hdr.Typ != typParty {
		return fmt.Errorf("jws: typ %q does not match expected %q", hdr.Typ, wantTyp)
	}
	switch sel {
	case PartyEdDSA:
		return CheckKind(hdr, wantTyp) // default allow-list: EdDSA only
	case PartyES256:
		if hdr.Alg != AlgES256 {
			return fmt.Errorf("jws: alg %q is not allowed for typ %q with ES256 selected",
				hdr.Alg, typParty)
		}
		return nil
	default:
		return fmt.Errorf("jws: unknown party key algorithm selection %d", sel)
	}
}

// RawSignatureToDER converts a raw 64-byte R||S signature (RFC 7518 section
// 3.4) to the ASN.1 DER ECDSA-Sig-Value structure (RFC 7515 appendix A.3).
//
// Parameters: raw is exactly 64 bytes, R then S, each a fixed 32-byte
// big-endian unsigned integer.
// Returns: the DER encoding and nil, or an error for any other length.
// Never panics.
func RawSignatureToDER(raw []byte) ([]byte, error) {
	if len(raw) != 2*32 {
		return nil, fmt.Errorf("jws: raw signature is %d bytes, want 64", len(raw))
	}
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return nil, fmt.Errorf("jws: raw signature to DER: %w", err)
	}
	return der, nil
}

// DERToRawSignature converts an ASN.1 DER ECDSA-Sig-Value structure to the
// raw 64-byte R||S encoding (RFC 7518 section 3.4). Each integer is left
// padded to exactly 32 bytes, so DER -> raw -> DER round-trips losslessly
// including a leading 0x00 prefix on a high-bit S. Trailing bytes after the
// structure, negative integers, and integers wider than 256 bits are
// rejected.
//
// Parameters: der is the ASN.1 DER encoding produced by e.g.
// ecdsa.SignASN1.
// Returns: exactly 64 raw bytes and nil, or an error. Never panics.
func DERToRawSignature(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("jws: DER signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("jws: DER signature: %d trailing bytes", len(rest))
	}
	if err := checkDERInt(sig.R, "R"); err != nil {
		return nil, err
	}
	if err := checkDERInt(sig.S, "S"); err != nil {
		return nil, err
	}
	raw := make([]byte, 2*32)
	sig.R.FillBytes(raw[:32]) // left-pad to 32 bytes — lossless round trip
	sig.S.FillBytes(raw[32:])
	return raw, nil
}

// checkDERInt validates one DER signature integer: present, non-negative,
// and at most 256 bits wide.
func checkDERInt(v *big.Int, name string) error {
	if v == nil || v.Sign() < 0 {
		return fmt.Errorf("jws: DER signature: %s is negative", name)
	}
	if v.BitLen() > 256 {
		return fmt.Errorf("jws: DER signature: %s is %d bits, want at most 256", name, v.BitLen())
	}
	return nil
}
