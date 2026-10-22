package jws_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// RFC 8037 Appendix A.3 Ed25519 JWS example. The key is the RFC 8033 first
// test vector (d = 32-byte seed, x = public key, base64url unpadded); the
// payload is "Example of Ed25519 signing"; the protected header is
// {"alg":"EdDSA"}. RFC 8032 Ed25519 signing is deterministic, so a byte-exact
// reproduction is possible.
const (
	rfc8037Seed     = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037Pub      = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfc8037Payload  = "Example of Ed25519 signing"
	rfc8037CompactJ = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc." +
		"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)

// rfc8037Key derives the RFC 8037 example Ed25519 key pair from its seed and
// asserts the derived public key equals the published one.
func rfc8037Key(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(rfc8037Seed)
	require.NoError(t, err)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	assert.Equal(t, rfc8037Pub, base64.RawURLEncoding.EncodeToString(pub))
	return priv, pub
}

// signRaw signs arbitrary protected-header JSON with the given key, forging
// headers the SDK's own signer would never produce.
func signRaw(t *testing.T, priv ed25519.PrivateKey, protected, payload string) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(protected)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := ed25519.Sign(priv, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestRFC8037Ed25519JWSExample asserts signing reproduces the RFC 8037
// Appendix A.3 compact JWS byte for byte and the example verifies.
func TestRFC8037Ed25519JWSExample(t *testing.T) {
	priv, pub := rfc8037Key(t)

	got, err := jws.SignEd25519(priv, jws.Header{Alg: jws.AlgEdDSA}, []byte(rfc8037Payload))
	require.NoError(t, err)
	assert.Equal(t, rfc8037CompactJ, got)

	hdr, payload, err := jws.VerifyEd25519(pub, []byte(rfc8037CompactJ))
	require.NoError(t, err)
	assert.Equal(t, jws.AlgEdDSA, hdr.Alg)
	assert.Equal(t, rfc8037Payload, string(payload))
}

// TestSignProtectedHeaderByteExact asserts the protected header serializes
// with exactly the members and order the SDK pins (alg, kid, typ) — the
// prerequisite for byte-exact golden signing.
func TestSignProtectedHeaderByteExact(t *testing.T) {
	priv, pub := rfc8037Key(t)
	kid := "VF2hp4earhJQVC1H_7xPVVINlkfxbuZ7p4YP30i6H9c"

	token, err := jws.SignEd25519(priv, jws.Header{
		Alg: jws.AlgEdDSA,
		Kid: kid,
		Typ: wire.TypParty,
	}, []byte(`{"iss":"pty-demo"}`))
	require.NoError(t, err)

	protected, ok := cutSegments(token)
	require.True(t, ok)
	decoded, err := base64.RawURLEncoding.DecodeString(protected)
	require.NoError(t, err)
	assert.Equal(t, `{"alg":"EdDSA","kid":"`+kid+`","typ":"ks-party+jwt"}`, string(decoded))

	hdr, payload, err := jws.VerifyEd25519(pub, []byte(token))
	require.NoError(t, err)
	require.NoError(t, jws.CheckKind(hdr, wire.TypParty))
	assert.Equal(t, kid, hdr.Kid)
	assert.Equal(t, `{"iss":"pty-demo"}`, string(payload))
}

// cutSegments returns the protected-header segment of a compact JWS.
func cutSegments(token string) (string, bool) {
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			return token[:i], true
		}
	}
	return "", false
}

// TestSignEd25519Rejects asserts signing never silently fixes a wrong alg and
// rejects malformed keys.
func TestSignEd25519Rejects(t *testing.T) {
	priv, _ := rfc8037Key(t)
	for _, alg := range []string{"", "ES256", "HS256", "none"} {
		_, err := jws.SignEd25519(priv, jws.Header{Alg: alg}, []byte("x"))
		require.Error(t, err, "alg %q", alg)
	}
	_, err := jws.SignEd25519(ed25519.PrivateKey("short"), jws.Header{Alg: jws.AlgEdDSA}, []byte("x"))
	require.Error(t, err)
}

// TestVerifyDenied asserts a wrong typ, a non-allow-listed alg, an unknown
// typ, a bad signature, or a malformed key is denied with an error — the
// signature layer (VerifyEd25519) and the token-kind layer (CheckKind)
// composed exactly as wire callers must compose them.
func TestVerifyDenied(t *testing.T) {
	priv, pub := rfc8037Key(t)

	// Corrupt one bit of the example signature.
	sigB64 := rfc8037CompactJ[strings.LastIndexByte(rfc8037CompactJ, '.')+1:]
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	require.NoError(t, err)
	sig[0] ^= 0x01
	badSig := rfc8037CompactJ[:strings.LastIndexByte(rfc8037CompactJ, '.')+1] +
		base64.RawURLEncoding.EncodeToString(sig)

	// A token signed by a different key must not verify either.
	_, otherPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	otherToken := signRaw(t, otherPriv, `{"alg":"EdDSA","typ":"ks-party+jwt"}`, "p")

	cases := map[string]struct {
		compact string
		wantTyp string
	}{
		"wrong typ":             {signRaw(t, priv, `{"alg":"EdDSA","typ":"ks-access+jwt"}`, "p"), wire.TypParty},
		"generic typ":           {signRaw(t, priv, `{"alg":"EdDSA","typ":"JWT"}`, "p"), wire.TypParty},
		"missing typ":           {signRaw(t, priv, `{"alg":"EdDSA"}`, "p"), wire.TypParty},
		"unknown typ":           {signRaw(t, priv, `{"alg":"EdDSA","typ":"ks-custom+jwt"}`, "p"), "ks-custom+jwt"},
		"alg HS256":             {signRaw(t, priv, `{"alg":"HS256","typ":"ks-party+jwt"}`, "p"), wire.TypParty},
		"alg none":              {signRaw(t, priv, `{"alg":"none","typ":"ks-party+jwt"}`, "p"), wire.TypParty},
		"bad signature":         {badSig, wire.TypParty},
		"signed by another key": {otherToken, wire.TypParty},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			hdr, _, err := jws.VerifyEd25519(pub, []byte(tc.compact))
			if err == nil {
				err = jws.CheckKind(hdr, tc.wantTyp)
			}
			require.Error(t, err)
		})
	}
}

// TestVerifyEd25519RejectsMalformedKey asserts a wrong-size public key is an
// error, never a panic.
func TestVerifyEd25519RejectsMalformedKey(t *testing.T) {
	_, _, err := jws.VerifyEd25519(ed25519.PublicKey("short"), []byte(rfc8037CompactJ))
	require.Error(t, err)
}

// TestAllowedAlgsTokenKindsRows pins the alg allow-list to the Token Kinds
// table: every row allows EdDSA by default (gateway rows EdDSA only), and
// any other typ allows nothing, so callers fail closed.
func TestAllowedAlgsTokenKindsRows(t *testing.T) {
	for _, typ := range wire.Typs() {
		assert.Equal(t, []string{jws.AlgEdDSA}, jws.AllowedAlgs(typ), "typ %s", typ)
	}
	for _, typ := range []string{"", "JWT", "ks-custom+jwt"} {
		assert.Nil(t, jws.AllowedAlgs(typ), "typ %q", typ)
	}
}

// TestCheckKindRequiresExactTyp asserts CheckKind demands exact typ equality
// in both directions, including the empty typ on either side.
func TestCheckKindRequiresExactTyp(t *testing.T) {
	require.Error(t, jws.CheckKind(jws.Header{Alg: jws.AlgEdDSA}, ""))
	require.Error(t, jws.CheckKind(jws.Header{Alg: jws.AlgEdDSA, Typ: wire.TypParty}, wire.TypAccess))
	require.NoError(t, jws.CheckKind(jws.Header{Alg: jws.AlgEdDSA, Typ: wire.TypParty}, wire.TypParty))
}

// TestParseRejectsMalformed asserts structurally invalid compact tokens and
// malformed protected headers are rejected with errors, never panics.
func TestParseRejectsMalformed(t *testing.T) {
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	cases := map[string]string{
		"empty":              "",
		"one segment":        "abc",
		"two segments":       "a.b",
		"four segments":      "a.b.c.d",
		"bad base64 header":  "!!.x.y",
		"empty header":       ".x.y",
		"empty signature":    "x.y.",
		"null header":        b64("null") + ".x.y",
		"array header":       b64("[]") + ".x.y",
		"number header":      b64(`{"alg":6}`) + ".x.y",
		"missing alg":        b64(`{"typ":"ks-party+jwt"}`) + ".x.y",
		"empty alg":          b64(`{"alg":""}`) + ".x.y",
		"non-string typ":     b64(`{"alg":"EdDSA","typ":7}`) + ".x.y",
		"payload not base64": b64(`{"alg":"EdDSA"}`) + ".!!.y",
	}
	for name, compact := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := jws.Parse([]byte(compact))
			require.Error(t, err)
		})
	}
}

// TestParseRoundTrip asserts a signed token parses into the exact header,
// payload, and signature segments the signer produced.
func TestParseRoundTrip(t *testing.T) {
	priv, _ := rfc8037Key(t)
	token, err := jws.SignEd25519(priv, jws.Header{Alg: jws.AlgEdDSA, Typ: wire.TypResult}, []byte("payload"))
	require.NoError(t, err)

	hdr, payload, sig, err := jws.Parse([]byte(token))
	require.NoError(t, err)
	assert.Equal(t, jws.Header{Alg: jws.AlgEdDSA, Typ: wire.TypResult}, hdr)
	assert.Equal(t, "payload", string(payload))
	assert.Len(t, sig, ed25519.SignatureSize)
}
