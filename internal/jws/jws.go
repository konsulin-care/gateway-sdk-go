package jws

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Header is the JWS protected header (RFC 7515 section 4.1) with the exact
// members this SDK produces and accepts: alg always, kid and typ when set.
// Signing serializes the members in exactly this field order, so identical
// inputs yield byte-identical protected headers. Parsing ignores members
// beyond these (RFC 7515 section 4.2) but never a missing or non-string
// alg — "alg" is REQUIRED (RFC 7515 section 4.1.1).
type Header struct {
	// Alg is the JWS "alg" header value (AlgEdDSA).
	Alg string `json:"alg"`
	// Kid is the key id: the RFC 7638 thumbprint of the signing key.
	Kid string `json:"kid,omitempty"`
	// Typ is the exact token kind (Token Kinds table row).
	Typ string `json:"typ,omitempty"`
}

// Parse splits a compact JWS (RFC 7515 section 7.1) into its decoded parts
// WITHOUT verifying the signature. It is the structural layer behind
// VerifyEd25519; tokens accepted on the wire must go through VerifyEd25519
// and CheckKind, never Parse alone.
//
// Parameters: compact is the full three-segment compact serialization.
// Returns: the protected header, payload bytes, signature bytes, and nil; or
// an error. Fail-closed: exactly three non-empty-signature base64url
// (unpadded) segments, a decodable JSON object header with a non-empty
// string alg. Never panics on malformed input.
func Parse(compact []byte) (Header, []byte, []byte, error) {
	hdr, _, payload, sig, err := parseCompact(compact)
	if err != nil {
		return Header{}, nil, nil, err
	}
	return hdr, payload, sig, nil
}

// CheckKind checks a parsed protected header against the expected token
// kind: the token's typ must equal wantTyp exactly (string equality in both
// directions — an empty typ on either side only matches an empty wantTyp,
// which AllowedAlgs then denies), and the header alg must be in the kind's
// allow-list (AllowedAlgs). Any mismatch denies — fail closed.
//
// Parameters: hdr is the header returned by Parse or VerifyEd25519; wantTyp
// is the exact typ of the row the caller is applying.
// Returns: nil when the header satisfies the row, or an error naming the
// mismatch. Never panics.
func CheckKind(hdr Header, wantTyp string) error {
	if hdr.Typ != wantTyp {
		return fmt.Errorf("jws: typ %q does not match expected %q", hdr.Typ, wantTyp)
	}
	for _, alg := range AllowedAlgs(wantTyp) {
		if hdr.Alg == alg {
			return nil
		}
	}
	return fmt.Errorf("jws: alg %q is not allowed for typ %q", hdr.Alg, wantTyp)
}

// parseCompact cuts a compact JWS into its decoded parts and the exact
// signing input (the first two segments joined by a dot), which the
// signature check must use verbatim.
func parseCompact(compact []byte) (Header, []byte, []byte, []byte, error) {
	if n := bytes.Count(compact, []byte{'.'}); n != 2 {
		return Header{}, nil, nil, nil,
			fmt.Errorf("jws: compact serialization: %d dots, want 2", n)
	}
	first := bytes.IndexByte(compact, '.')
	last := bytes.LastIndexByte(compact, '.')
	signingInput := compact[:last]

	if first == 0 {
		return Header{}, nil, nil, nil, errors.New("jws: compact serialization: empty protected header")
	}
	protected, err := decodeSegment(compact[:first], "protected header")
	if err != nil {
		return Header{}, nil, nil, nil, err
	}
	payload, err := decodeSegment(compact[first+1:last], "payload")
	if err != nil {
		return Header{}, nil, nil, nil, err
	}
	sig, err := decodeSegment(compact[last+1:], "signature")
	if err != nil {
		return Header{}, nil, nil, nil, err
	}
	if len(sig) == 0 {
		return Header{}, nil, nil, nil, errors.New("jws: compact serialization: empty signature")
	}

	var hdr Header
	if err := json.Unmarshal(protected, &hdr); err != nil {
		return Header{}, nil, nil, nil, fmt.Errorf("jws: protected header: %w", err)
	}
	if hdr.Alg == "" {
		return Header{}, nil, nil, nil, errors.New("jws: protected header: missing alg")
	}
	return hdr, signingInput, payload, sig, nil
}

// decodeSegment base64url-decodes one compact segment (unpadded, RFC 7515
// section 2) with a segment-named error.
func decodeSegment(seg []byte, name string) ([]byte, error) {
	out, err := base64.RawURLEncoding.DecodeString(string(seg))
	if err != nil {
		return nil, fmt.Errorf("jws: compact serialization: %s: %w", name, err)
	}
	return out, nil
}
