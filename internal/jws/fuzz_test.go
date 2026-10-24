package jws_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
)

// FuzzParse asserts compact JWS parsing never panics on arbitrary input.
// When a fuzzed token happens to parse, the Ed25519 signature layer and the
// token-kind layer run over it too, so the whole verify path is fuzzed —
// any malformed input must yield an error, never a panic.
func FuzzParse(f *testing.F) {
	seed, err := base64.RawURLEncoding.DecodeString(rfc8037Seed)
	if err != nil {
		f.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	seeds := []string{
		rfc8037CompactJ,
		mustSign(f, priv, `{"alg":"EdDSA","kid":"k1","typ":"ks-party+jwt"}`),
		mustSign(f, priv, `{"alg":"none","typ":"ks-party+jwt"}`),
		"",
		".",
		"..",
		"...",
		"a.b.c",
		"!!.x.y",
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"`)) + ".eA.eA",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, compact []byte) {
		hdr, _, _, err := jws.Parse(compact)
		if err != nil {
			return
		}
		if _, _, err := jws.VerifyEd25519(pub, compact); err == nil {
			_ = jws.CheckKind(hdr, "ks-party+jwt")
		}
	})
}

// mustSign signs a seed header literal with the fuzz seed key, failing the
// seed build otherwise. The literal is a valid header JSON by construction;
// json is decoded leniently here because "alg":"none" is a deliberate seed.
func mustSign(f *testing.F, priv ed25519.PrivateKey, protected string) string {
	f.Helper()
	var hdr jws.Header
	if err := json.Unmarshal([]byte(protected), &hdr); err != nil {
		f.Fatal(err)
	}
	// SignEd25519 requires alg EdDSA; seed non-EdDSA headers by hand so the
	// fuzz corpus reaches the alg-rejection path.
	if hdr.Alg != jws.AlgEdDSA {
		input := base64.RawURLEncoding.EncodeToString([]byte(protected)) +
			"." + base64.RawURLEncoding.EncodeToString([]byte("seed payload"))
		sig := ed25519.Sign(priv, []byte(input))
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	token, err := jws.SignEd25519(priv, hdr, []byte("seed payload"))
	if err != nil {
		f.Fatal(err)
	}
	return token
}
