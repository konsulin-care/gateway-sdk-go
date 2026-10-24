package envelope

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 7748 section 6.1 X25519 Diffie-Hellman vector (hex): Alice's static
// key pair, Bob's public key, and the published shared secret — the exact
// four values the Go toolchain's crypto/ecdh test vector pins. Bob's
// private scalar is deliberately absent: no authoritative copy of that
// constant is vendored in this repository and a recalled value cannot be
// trusted (one derived the wrong public key at runtime), so the vector
// test below pre-pins the agreement instead of re-deriving it from a
// scalar. RFC 8037 Appendix A.6 performs exactly this agreement inside
// its ECDH-ES JWE example; its JOSE-wrapped constants are likewise not
// pinned (the ECDH-ES composition is pinned by
// TestConcatKDFRFC7518AppendixC and the envelope contract tests).
const (
	rfc7748AlicePriv = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	rfc7748AlicePub  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	rfc7748BobPub    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	rfc7748Shared    = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
)

// x25519HexPrivate decodes a hex-encoded X25519 private scalar: RFC 7748
// publishes its vectors in hex.
func x25519HexPrivate(t *testing.T, h string) *ecdh.PrivateKey {
	t.Helper()
	raw, err := hex.DecodeString(h)
	require.NoError(t, err)
	key, err := ecdh.X25519().NewPrivateKey(raw)
	require.NoError(t, err)
	return key
}

// x25519HexPublic decodes a hex-encoded X25519 public key coordinate.
func x25519HexPublic(t *testing.T, h string) *ecdh.PublicKey {
	t.Helper()
	raw, err := hex.DecodeString(h)
	require.NoError(t, err)
	key, err := ecdh.X25519().NewPublicKey(raw)
	require.NoError(t, err)
	return key
}

// pinnedDecrypter stands in for Bob's private key in the RFC 7748
// section 6.1 composition below: the published shared secret is returned
// for any ephemeral, so Open runs its full pipeline (header, epk, IV/tag
// lengths, AAD, CEK derivation) against the pinned agreement without
// needing an untrustworthy recalled scalar.
type pinnedDecrypter struct{ z []byte }

var _ Decrypter = pinnedDecrypter{}

// ECDH returns the pinned shared secret for any ephemeral public key.
func (d pinnedDecrypter) ECDH(*ecdh.PublicKey) ([]byte, error) { return d.z, nil }

// TestX25519SharedSecretRFC7748Vector pins the X25519 key agreement the
// ECDH-ES envelope performs to the canonical RFC 7748 section 6.1 vector
// as pinned by the Go toolchain's crypto/ecdh tests: Alice's published
// scalar derives her published public key, and the agreement with Bob's
// published public key equals the published shared secret. It then
// composes the same published keys through this package's envelope: a
// seal taking Alice's key as the injected ephemeral to Bob's published
// public key carries Alice's published coordinate as the protected epk,
// and opens byte-identical when the recipient's shared secret is the
// published one — so the message's CEK is provably derived from the
// pinned shared secret.
func TestX25519SharedSecretRFC7748Vector(t *testing.T) {
	alice := x25519HexPrivate(t, rfc7748AlicePriv)
	assert.Equal(t, rfc7748AlicePub, hex.EncodeToString(alice.PublicKey().Bytes()),
		"Alice's published scalar must derive her published public key")

	bobPub := x25519HexPublic(t, rfc7748BobPub)
	z, err := alice.ECDH(bobPub)
	require.NoError(t, err)
	assert.Equal(t, rfc7748Shared, hex.EncodeToString(z),
		"ECDH(Alice, Bob) must equal the RFC 7748 section 6.1 shared secret")

	// Compose the published agreement through the envelope: Alice's key
	// acts as the sender's ephemeral, Bob's published public key as the
	// recipient, so the sealed CEK is derived from the published shared
	// secret.
	payload := []byte("rfc-pinned payload")
	compact, err := seal(payload, "rfc-recipient", bobPub, alice)
	require.NoError(t, err)

	parts := strings.Split(compact, ".")
	require.Len(t, parts, 5, "a compact JWE has five segments")
	var header protectedHeader
	require.NoError(t, json.Unmarshal(b64(t, parts[0]), &header))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(alice.PublicKey().Bytes()),
		header.Epk.X, "the protected epk must carry the published ephemeral public key")

	opened, err := Open(compact, pinnedDecrypter{z: z})
	require.NoError(t, err)
	assert.Equal(t, payload, opened,
		"a message sealed over the pinned agreement must open with the published shared secret")
}

// TestConcatKDFRFC7518AppendixC asserts the SP 800-56A Concat KDF
// (SHA-256) against the published RFC 7518 Appendix C vectors: the
// A128GCM vector of the appendix (Z, AlgorithmID "A128GCM", PartyU
// "Alice", PartyV "Bob", keydatalen 128) derives the published 16-byte
// keying material. A KDF deviation is a test failure, never a runtime
// fallback.
func TestConcatKDFRFC7518AppendixC(t *testing.T) {
	z := []byte{
		158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
		38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
		140, 254, 144, 196,
	}
	want := []byte{
		86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26,
	}
	got := concatKDF(z, []byte("A128GCM"), []byte("Alice"), []byte("Bob"), 128)
	assert.Equal(t, want, got, "RFC 7518 Appendix C Concat KDF vector must derive byte-exact")
}

// newRecipient generates a recipient X25519 use:enc key pair for tests.
func newRecipient(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return key
}

// b64 decodes a base64url (unpadded) string for test assertions.
func b64(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err)
	return raw
}

// headerJSON re-encodes a modified protected header over the given
// segments so malformed-envelope cases can be built precisely.
func headerJSON(t *testing.T, hdr map[string]any, iv, ct, tag string) string {
	t.Helper()
	raw, err := json.Marshal(hdr)
	require.NoError(t, err)
	return strings.Join([]string{
		base64.RawURLEncoding.EncodeToString(raw), "", iv, ct, tag,
	}, ".")
}

// TestSealContractHeaderAndSegments asserts the sealed token matches the
// normative JWE Envelope: five segments, an empty encrypted-key segment,
// a protected header with alg ECDH-ES, enc A256GCM, the recipient kid,
// and an OKP/X25519 epk, a 12-byte IV, a 16-byte tag, and a byte-exact
// Open round trip.
func TestSealContractHeaderAndSegments(t *testing.T) {
	recipient := newRecipient(t)
	payload := []byte(`{"amount":100}`)

	compact, err := Seal(payload, "recipient-kid", recipient.PublicKey())
	require.NoError(t, err)

	parts := strings.Split(compact, ".")
	require.Len(t, parts, 5, "a compact JWE has five segments")
	assert.Empty(t, parts[1], "the encrypted-key segment must be empty (ECDH-ES direct)")

	var header protectedHeader
	require.NoError(t, json.Unmarshal(b64(t, parts[0]), &header))
	assert.Equal(t, "ECDH-ES", header.Alg)
	assert.Equal(t, "A256GCM", header.Enc)
	assert.Equal(t, "recipient-kid", header.Kid)
	assert.Equal(t, "OKP", header.Epk.Kty)
	assert.Equal(t, "X25519", header.Epk.Crv)
	assert.Len(t, b64(t, header.Epk.X), 32, "epk.x is a 32-byte X25519 coordinate")

	assert.Len(t, b64(t, parts[2]), 12, "the IV is 12 bytes")
	assert.Len(t, b64(t, parts[4]), 16, "the tag is 16 bytes")

	opened, err := Open(compact, recipient)
	require.NoError(t, err)
	assert.Equal(t, payload, opened)
}

// TestSealFreshEphemeralPerMessage asserts two seals of the same payload
// to the same recipient differ (fresh ephemeral epk and IV per message)
// yet both open to the original payload.
func TestSealFreshEphemeralPerMessage(t *testing.T) {
	recipient := newRecipient(t)
	payload := []byte("same payload")

	first, err := Seal(payload, "kid", recipient.PublicKey())
	require.NoError(t, err)
	second, err := Seal(payload, "kid", recipient.PublicKey())
	require.NoError(t, err)
	assert.NotEqual(t, first, second, "two seals of one payload must differ (fresh epk/IV)")

	for _, compact := range []string{first, second} {
		opened, err := Open(compact, recipient)
		require.NoError(t, err)
		assert.Equal(t, payload, opened)
	}
}

// TestOpenRejectsMalformedEnvelope asserts every malformed shape is
// rejected with a nil plaintext before any plaintext is produced.
func TestOpenRejectsMalformedEnvelope(t *testing.T) {
	recipient := newRecipient(t)
	compact, err := Seal([]byte("payload"), "kid", recipient.PublicKey())
	require.NoError(t, err)
	parts := strings.Split(compact, ".")
	iv, ct, tag := parts[2], parts[3], parts[4]

	validEpkX := base64.RawURLEncoding.EncodeToString(x25519HexPublic(t, rfc7748AlicePub).Bytes())
	goodEpk := map[string]any{"kty": "OKP", "crv": "X25519", "x": validEpkX}
	base := map[string]any{"alg": "ECDH-ES", "enc": "A256GCM", "kid": "kid", "epk": goodEpk}
	mod := func(kv map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range kv {
			out[k] = v
		}
		return out
	}

	cases := []struct{ name, compact string }{
		{"four segments", strings.Join(parts[:4], ".")},
		{"six segments", compact + ".extra"},
		{"non-empty encrypted key", strings.Join([]string{parts[0], "ZQ", iv, ct, tag}, ".")},
		{"header not base64", "@@@." + strings.Join(parts[1:], ".")},
		{"header not json", base64.RawURLEncoding.EncodeToString([]byte("nope")) + "." + strings.Join(parts[1:], ".")},
		{"wrong alg", headerJSON(t, mod(map[string]any{"alg": "ECDH-ES+A256GCM"}), iv, ct, tag)},
		{"wrong enc", headerJSON(t, mod(map[string]any{"enc": "A128GCM"}), iv, ct, tag)},
		{"missing kid", headerJSON(t, mod(map[string]any{"kid": ""}), iv, ct, tag)},
		{"epk not OKP", headerJSON(t, mod(map[string]any{"epk": map[string]any{"kty": "EC", "crv": "P-256", "x": validEpkX}}), iv, ct, tag)},
		{"epk wrong crv", headerJSON(t, mod(map[string]any{"epk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": validEpkX}}), iv, ct, tag)},
		{"epk bad x", headerJSON(t, mod(map[string]any{"epk": map[string]any{"kty": "OKP", "crv": "X25519", "x": "AAAA"}}), iv, ct, tag)},
		{"short IV", headerJSON(t, base, base64.RawURLEncoding.EncodeToString(b64(t, iv)[:11]), ct, tag)},
		{"short tag", headerJSON(t, base, iv, ct, base64.RawURLEncoding.EncodeToString(b64(t, tag)[:15]))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plaintext, err := Open(tc.compact, recipient)
			assert.Error(t, err)
			assert.Nil(t, plaintext, "a rejected envelope must return nil plaintext")
		})
	}

	t.Run("nil Decrypter", func(t *testing.T) {
		plaintext, err := Open(compact, nil)
		assert.Error(t, err)
		assert.Nil(t, plaintext)
	})
}

// TestOpenRejectsTamperedCiphertext asserts a flipped bit in the
// ciphertext, the tag, or the protected header each fails
// authentication with a nil plaintext.
func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	recipient := newRecipient(t)
	payload := []byte("sensitive payload")
	compact, err := Seal(payload, "kid", recipient.PublicKey())
	require.NoError(t, err)
	parts := strings.Split(compact, ".")

	flip := func(segment string) string {
		raw := b64(t, segment)
		raw[0] ^= 0x01
		return base64.RawURLEncoding.EncodeToString(raw)
	}

	tamperedCT := strings.Join([]string{parts[0], parts[1], parts[2], flip(parts[3]), parts[4]}, ".")
	tamperedTag := strings.Join([]string{parts[0], parts[1], parts[2], parts[3], flip(parts[4])}, ".")

	var header protectedHeader
	require.NoError(t, json.Unmarshal(b64(t, parts[0]), &header))
	header.Kid = "other-kid"
	tamperedHdrRaw, err := json.Marshal(header)
	require.NoError(t, err)
	tamperedHdr := strings.Join([]string{
		base64.RawURLEncoding.EncodeToString(tamperedHdrRaw), parts[1], parts[2], parts[3], parts[4],
	}, ".")

	for _, tc := range []struct{ name, compact string }{
		{"tampered ciphertext", tamperedCT},
		{"tampered tag", tamperedTag},
		{"tampered header", tamperedHdr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plaintext, err := Open(tc.compact, recipient)
			assert.Error(t, err)
			assert.Nil(t, plaintext, "a tampered envelope must return nil plaintext")
		})
	}
}

// pepperShapedPayload returns a deterministic 32-byte payload in the shape
// of the federation pepper (the concrete value a party opens an envelope
// for), so round-trip and tamper tests exercise the exact size that matters.
func pepperShapedPayload() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(i*7 + 1)
	}
	return out
}

// TestSealOpenRoundTripByteIdentical asserts the SDK-ENV-C01 round trip is
// byte-identical for the three payload shapes that matter: an empty
// payload, a 32-byte pepper-shaped payload, and a large (1 MiB) payload.
// Each payload seals to a compact JWE and opens back to exactly the bytes
// that were sealed — no truncation, no padding, no mutation at any size.
func TestSealOpenRoundTripByteIdentical(t *testing.T) {
	recipient := newRecipient(t)

	large := make([]byte, 1<<20)
	for i := range large {
		large[i] = byte(i % 251)
	}

	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"32-byte pepper-shaped", pepperShapedPayload()},
		{"large 1 MiB", large},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compact, err := Seal(tc.payload, "round-trip-kid", recipient.PublicKey())
			require.NoError(t, err)

			opened, err := Open(compact, recipient)
			require.NoError(t, err)
			assert.Equal(t, len(tc.payload), len(opened),
				"the round trip must return exactly as many bytes as were sealed")
			assert.True(t, bytes.Equal(tc.payload, opened),
				"seal then open must be byte-identical for a %s payload", tc.name)
		})
	}
}

// TestSealOpenTamperFails asserts the SDK-ENV-C01 deny half exhaustively:
// flipping ANY single bit of the ciphertext or of the authentication tag
// fails Open with a nil plaintext. Every byte of both segments is walked
// across all eight bit positions against a 32-byte (pepper-shaped)
// payload, one bit changed per attempt relative to the original token.
func TestSealOpenTamperFails(t *testing.T) {
	recipient := newRecipient(t)
	payload := pepperShapedPayload()
	compact, err := Seal(payload, "tamper-kid", recipient.PublicKey())
	require.NoError(t, err)
	parts := strings.Split(compact, ".")
	require.Len(t, parts, 5, "a compact JWE has five segments")
	origCT, origTag := parts[3], parts[4]

	segments := []struct {
		name  string
		index int
		orig  string
	}{
		{"ciphertext", 3, origCT},
		{"tag", 4, origTag},
	}
	for _, seg := range segments {
		raw := b64(t, seg.orig)
		require.NotEmpty(t, raw)
		for i := range raw {
			for bit := 0; bit < 8; bit++ {
				mutated := append([]byte(nil), raw...)
				mutated[i] ^= 1 << bit

				mutatedParts := []string{parts[0], parts[1], parts[2], origCT, origTag}
				mutatedParts[seg.index] = base64.RawURLEncoding.EncodeToString(mutated)
				tampered := strings.Join(mutatedParts, ".")

				plaintext, err := Open(tampered, recipient)
				assert.Error(t, err,
					"flipping bit %d of byte %d of the %s must fail Open", bit, i, seg.name)
				assert.Nil(t, plaintext,
					"a tampered envelope must return nil plaintext (bit %d of byte %d of the %s)",
					bit, i, seg.name)
			}
		}
	}
}
