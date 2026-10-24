package jws

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// SignEd25519 signs payload into a compact JWS (RFC 7515 section 7.1) with
// alg EdDSA. hdr.Alg must be AlgEdDSA — a wrong or empty alg is an error,
// never silently fixed, so this signer can never produce another algorithm's
// token. RFC 8032 Ed25519 is deterministic: identical key, header, and
// payload bytes yield an identical token, which the golden vectors rely on.
//
// Parameters: priv is the Ed25519 private key (64 bytes); hdr is the
// protected header (kid/typ optional); payload is the raw (unencoded) JSON
// payload.
// Returns: the compact JWS and nil, or an error. Never panics.
func SignEd25519(priv ed25519.PrivateKey, hdr Header, payload []byte) (string, error) {
	if hdr.Alg != AlgEdDSA {
		return "", fmt.Errorf("jws: sign Ed25519: alg must be %q, got %q", AlgEdDSA, hdr.Alg)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("jws: sign Ed25519: private key is %d bytes, want %d",
			len(priv), ed25519.PrivateKeySize)
	}
	protected, err := json.Marshal(hdr) // field order: alg, kid, typ — byte-exact
	if err != nil {
		return "", fmt.Errorf("jws: sign Ed25519: protected header: %w", err)
	}
	input := base64.RawURLEncoding.EncodeToString(protected) +
		"." + base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(priv, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyEd25519 verifies the Ed25519 signature of a compact JWS and its alg
// header: the protected header must parse (see Parse), state alg EdDSA
// exactly — any other alg, allow-listed or not, is denied here — and the
// signature must verify over the token's exact signing input with the key
// the caller selected by kid.
//
// This is the signature layer only: callers MUST additionally run CheckKind
// with the expected typ before accepting the token.
//
// Parameters: pub is the Ed25519 public key (32 bytes) the caller resolved
// from the token's kid header (JWKS only, kid-only selection); compact is
// the token.
// Returns: the protected header, payload bytes, and nil; or an error. Any
// failure denies (fail closed); never panics.
func VerifyEd25519(pub ed25519.PublicKey, compact []byte) (Header, []byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Header{}, nil, fmt.Errorf("jws: verify Ed25519: public key is %d bytes, want %d",
			len(pub), ed25519.PublicKeySize)
	}
	hdr, signingInput, payload, sig, err := parseCompact(compact)
	if err != nil {
		return Header{}, nil, err
	}
	if hdr.Alg != AlgEdDSA {
		return Header{}, nil, fmt.Errorf("jws: verify Ed25519: alg %q is not allowed", hdr.Alg)
	}
	if !ed25519.Verify(pub, signingInput, sig) {
		return Header{}, nil, errors.New("jws: verify Ed25519: signature verification failed")
	}
	return hdr, payload, nil
}
