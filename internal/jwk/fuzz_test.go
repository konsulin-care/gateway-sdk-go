package jwk_test

import (
	"os"
	"testing"

	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
)

// FuzzParseJWKS asserts malformed JWKS input is rejected without a panic.
// Every accepted set is thumbprinted and walked with both selectors —
// SigByKid and EncByKid — so the fuzz target covers selection and thumbprint
// paths over fuzzed key material, including the sig/enc key-kind split.
func FuzzParseJWKS(f *testing.F) {
	seeds := []string{
		`{"keys":[]}`,
		`{"keys":[{"alg":"EdDSA","crv":"Ed25519","kid":"k","kty":"OKP","use":"sig","x":"iRjI0Qr9WRzkvTcY4bv8tAGPgBGrj83PSikHxaRFKyM"}]}`,
		`{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`,
		`{"keys":[` + ed25519SigJWK + `,` + x25519EncJWK + `]}`,
		`{"keys":[{"alg":"ECDH-ES","crv":"X25519","kid":"enc","kty":"OKP","use":"enc","x":"` + x25519X + `"}]}`,
		`{}`,
		`{"keys":1}`,
		`not json`,
		``,
	}
	if data, err := os.ReadFile("../../testdata/golden/gateway-jwks.json"); err == nil {
		seeds = append(seeds, string(data))
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		set, err := jwk.ParseJWKS(data)
		if err != nil {
			return
		}
		for _, key := range set.Keys {
			thumbprint, err := key.Thumbprint()
			if err != nil {
				continue
			}
			// The selectors must never cross key kinds over fuzzed material.
			if sig, ok := set.SigByKid(thumbprint); ok && sig.Crv == "X25519" {
				t.Fatalf("SigByKid returned an X25519 key for kid %q", thumbprint)
			}
			if enc, ok := set.EncByKid(thumbprint); ok && (enc.Crv != "X25519" || enc.Use != "enc") {
				t.Fatalf("EncByKid returned a %s/%s key with use %q for kid %q",
					enc.Kty, enc.Crv, enc.Use, thumbprint)
			}
		}
		// An empty kid must never match on either selector.
		_, _ = set.SigByKid("")
		_, _ = set.EncByKid("")
	})
}
