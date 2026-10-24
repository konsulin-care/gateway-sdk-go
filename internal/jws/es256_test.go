package jws_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// RFC 7515 Appendix A.3 ES256 example: protected header {"alg":"ES256"},
// payload the joe/is_root JSON document, EC P-256 key published as JWK, and
// the JWS Signature which is the raw R||S concatenation (RFC 7518 section
// 3.4). ECDSA is randomized, so only verification — never signing — can
// reproduce this published token.
const (
	rfc7515a3Compact = "eyJhbGciOiJFUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
		"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
		"pmWQxfKTUJqPP3-Kg6NU1Q"
	rfc7515a3X = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	rfc7515a3Y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
	rfc7515a3D = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
	// rfc7515a3R and rfc7515a3S are the RFC's R and S octet sequences.
	rfc7515a3R = "0ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac3169ea665"
	rfc7515a3S = "c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f8a83a354d5"
	// rfc7515a3DER is the ASN.1 DER ECDSA-Sig-Value of the same (R, S).
	rfc7515a3DER = "304502200ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac31" +
		"69ea665022100c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f" +
		"8a83a354d5"
)

// mustHex decodes a hex literal, failing the test otherwise.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// rfc7515Key rebuilds the RFC 7515 A.3 EC P-256 private key from its
// published d JWK member; ParseRawPrivateKey recomputes the public point.
func rfc7515Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	d, err := base64.RawURLEncoding.DecodeString(rfc7515a3D)
	require.NoError(t, err)
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	require.NoError(t, err)
	// The recomputed public point must equal the RFC-published x and y.
	pubBytes, err := priv.PublicKey.Bytes() // uncompressed 0x04||X||Y
	require.NoError(t, err)
	rawURL := func(s string) []byte {
		b, dErr := base64.RawURLEncoding.DecodeString(s)
		require.NoError(t, dErr)
		return b
	}
	wantPoint := append([]byte{0x04}, rawURL(rfc7515a3X)...)
	wantPoint = append(wantPoint, rawURL(rfc7515a3Y)...)
	require.Equal(t, wantPoint, pubBytes)
	return priv
}

// TestRFC7515A3ES256Vector asserts the published RFC 7515 Appendix A.3
// token verifies with the published key, and that its JWS Signature is the
// raw 64-byte R||S encoding of the RFC's R and S values.
func TestRFC7515A3ES256Vector(t *testing.T) {
	priv := rfc7515Key(t)

	hdr, payload, err := jws.VerifyES256(&priv.PublicKey, []byte(rfc7515a3Compact))
	require.NoError(t, err)
	assert.Equal(t, jws.AlgES256, hdr.Alg)
	assert.Empty(t, hdr.Typ)
	assert.Contains(t, string(payload), `"iss":"joe"`)
	assert.Contains(t, string(payload), `"http://example.com/is_root":true`)

	_, _, sig, err := jws.Parse([]byte(rfc7515a3Compact))
	require.NoError(t, err)
	want := mustHex(t, rfc7515a3R+rfc7515a3S)
	assert.Equal(t, want, sig)
}

// TestDERRawConversionRFCVector asserts the DER form of the RFC A.3 (R, S)
// matches the published octets and that DER <-> raw R||S conversion is
// lossless in both directions.
func TestDERRawConversionRFCVector(t *testing.T) {
	raw := mustHex(t, rfc7515a3R+rfc7515a3S)
	wantDER := mustHex(t, rfc7515a3DER)

	der, err := jws.RawSignatureToDER(raw)
	require.NoError(t, err)
	assert.Equal(t, wantDER, der)

	back, err := jws.DERToRawSignature(wantDER)
	require.NoError(t, err)
	assert.Equal(t, raw, back)
}

// TestSignES256VerifyRoundTrip asserts an explicitly selected ES256 signing
// call produces a byte-exact protected header, a 64-byte raw R||S signature,
// and a token the ES256 verify path plus the opt-in kind check accept.
func TestSignES256VerifyRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kid := "VF2hp4earhJQVC1H_7xPVVINlkfxbuZ7p4YP30i6H9c"

	token, err := jws.SignES256(priv, jws.Header{
		Alg: jws.AlgES256,
		Kid: kid,
		Typ: wire.TypParty,
	}, []byte(`{"iss":"pty-demo"}`))
	require.NoError(t, err)

	protected := strings.Split(token, ".")[0]
	decoded, err := base64.RawURLEncoding.DecodeString(protected)
	require.NoError(t, err)
	assert.Equal(t, `{"alg":"ES256","kid":"`+kid+`","typ":"ks-party+jwt"}`, string(decoded))

	hdr, payload, err := jws.VerifyES256(&priv.PublicKey, []byte(token))
	require.NoError(t, err)
	assert.Equal(t, kid, hdr.Kid)
	assert.Equal(t, `{"iss":"pty-demo"}`, string(payload))
	_, _, sig, err := jws.Parse([]byte(token))
	require.NoError(t, err)
	assert.Len(t, sig, 64)

	// The ES256 opt-in is explicit: the default selection still denies.
	require.NoError(t, jws.CheckKindParty(hdr, wire.TypParty, jws.PartyES256))
	require.Error(t, jws.CheckKindParty(hdr, wire.TypParty, jws.PartyEdDSA))
	require.Error(t, jws.CheckKind(hdr, wire.TypParty))
}

// TestES256NeverDefault asserts ES256 is unreachable without an explicit
// opt-in: the default allow-list and kind check never accept it, the
// Ed25519 signer never silently produces it, the ES256 signer demands an
// explicit ES256 header, the opt-in applies to party keys only, and the two
// verify paths are alg-exclusive.
func TestES256NeverDefault(t *testing.T) {
	priv := rfc7515Key(t)
	partyHdr := jws.Header{Alg: jws.AlgES256, Typ: wire.TypParty}

	// Default allow-list and checks deny ES256 for every token kind.
	for _, typ := range wire.Typs() {
		assert.NotContains(t, jws.AllowedAlgs(typ), jws.AlgES256, "typ %s", typ)
	}
	require.Error(t, jws.CheckKind(partyHdr, wire.TypParty))
	require.Error(t, jws.CheckKindParty(partyHdr, wire.TypParty, jws.PartyEdDSA))
	// An unknown or out-of-range selection also denies (fail closed).
	require.Error(t, jws.CheckKindParty(partyHdr, wire.TypParty, jws.PartyAlg(99)))

	// Signing without explicit ES256 selection never yields an ES256 token:
	// SignEd25519 rejects an ES256 header (asserted in jws_test.go) and
	// SignES256 rejects every non-ES256 header instead of silently fixing it.
	for _, alg := range []string{"", jws.AlgEdDSA, "HS256", "none"} {
		_, err := jws.SignES256(priv, jws.Header{Alg: alg}, []byte("x"))
		require.Error(t, err, "alg %q", alg)
	}
	_, err := jws.SignES256(nil, partyHdr, []byte("x"))
	require.Error(t, err)

	// The opt-in is limited to the party key kind.
	require.Error(t, jws.CheckKindParty(partyHdr, wire.TypAccess, jws.PartyES256))
	require.Error(t, jws.CheckKindParty(partyHdr, "", jws.PartyES256))

	// Verify paths are alg-exclusive in both directions.
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edTok, err := jws.SignEd25519(edPriv,
		jws.Header{Alg: jws.AlgEdDSA, Typ: wire.TypParty}, []byte("x"))
	require.NoError(t, err)
	_, _, err = jws.VerifyES256(&priv.PublicKey, []byte(edTok))
	require.Error(t, err)
	_, _, err = jws.VerifyEd25519(edPub, []byte(rfc7515a3Compact))
	require.Error(t, err)
}

// TestDERRawInteropSignASN1 asserts signatures produced by the stdlib DER
// signer (ecdsa.SignASN1) verify after DER -> raw conversion, and that the
// DER -> raw -> DER round trip is byte-identical.
func TestDERRawInteropSignASN1(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	hdr := jws.Header{Alg: jws.AlgES256, Typ: wire.TypParty}
	protected, err := json.Marshal(hdr)
	require.NoError(t, err)
	input := base64.RawURLEncoding.EncodeToString(protected) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"pty-demo"}`))
	digest := sha256.Sum256([]byte(input))

	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	require.NoError(t, err)
	raw, err := jws.DERToRawSignature(der)
	require.NoError(t, err)
	assert.Len(t, raw, 64)
	derBack, err := jws.RawSignatureToDER(raw)
	require.NoError(t, err)
	assert.Equal(t, der, derBack)

	token := input + "." + base64.RawURLEncoding.EncodeToString(raw)
	hdrOut, _, err := jws.VerifyES256(&priv.PublicKey, []byte(token))
	require.NoError(t, err)
	assert.Equal(t, jws.AlgES256, hdrOut.Alg)
}

// TestDERConversionRejects asserts malformed raw or DER signatures are
// rejected with errors, never panics.
func TestDERConversionRejects(t *testing.T) {
	goodRaw := mustHex(t, rfc7515a3R+rfc7515a3S)
	for _, n := range []int{0, 1, 63, 65, 128} {
		_, err := jws.RawSignatureToDER(make([]byte, n))
		require.Error(t, err, "raw len %d", n)
	}
	// High-bit and zero values still round-trip losslessly.
	hi := append([]byte{0xff}, goodRaw[1:]...)
	der, err := jws.RawSignatureToDER(hi)
	require.NoError(t, err)
	back, err := jws.DERToRawSignature(der)
	require.NoError(t, err)
	assert.Equal(t, hi, back)

	marshalInts := func(is ...*big.Int) []byte {
		b, mErr := asn1.Marshal(struct {
			R, S *big.Int
		}{is[0], is[1]})
		require.NoError(t, mErr)
		return b
	}
	big257 := new(big.Int).Lsh(big.NewInt(1), 256)
	cases := map[string][]byte{
		"empty":           {},
		"garbage":         []byte("not DER"),
		"truncated":       mustHex(t, rfc7515a3DER)[:10],
		"trailing bytes":  append(mustHex(t, rfc7515a3DER), 0x00),
		"negative":        marshalInts(big.NewInt(-1), big.NewInt(1)),
		"integer too big": marshalInts(big257, big.NewInt(1)),
	}
	for name, der := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := jws.DERToRawSignature(der)
			require.Error(t, err)
		})
	}
}

// TestVerifyES256Rejects asserts a bad signature, a wrong-length signature
// segment, or a malformed key is denied with an error, never a panic.
func TestVerifyES256Rejects(t *testing.T) {
	priv := rfc7515Key(t)
	parts := strings.Split(rfc7515a3Compact, ".")

	sig := mustHex(t, rfc7515a3R+rfc7515a3S)
	sig[0] ^= 0x01
	flat := strings.Join(append(parts[:2:2],
		base64.RawURLEncoding.EncodeToString(sig)), ".")
	_, _, err := jws.VerifyES256(&priv.PublicKey, []byte(flat))
	require.Error(t, err)

	// A DER-length signature in the compact segment is not 64 raw bytes.
	derSig := strings.Join(append(parts[:2:2],
		base64.RawURLEncoding.EncodeToString(mustHex(t, rfc7515a3DER))), ".")
	_, _, err = jws.VerifyES256(&priv.PublicKey, []byte(derSig))
	require.Error(t, err)

	_, _, err = jws.VerifyES256(nil, []byte(rfc7515a3Compact))
	require.Error(t, err)
	_, _, err = jws.VerifyES256(&ecdsa.PublicKey{Curve: elliptic.P521()},
		[]byte(rfc7515a3Compact))
	require.Error(t, err)
}
