package jwk_test

import (
	"os"
	"testing"

	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
)

// FuzzParseJWKS asserts malformed JWKS input is rejected without a panic.
// Every accepted set is walked kid-only and thumbprinted, so the fuzz target
// covers the selection and thumbprint paths over fuzzed key material too.
func FuzzParseJWKS(f *testing.F) {
	seeds := []string{
		`{"keys":[]}`,
		`{"keys":[{"alg":"EdDSA","crv":"Ed25519","kid":"k","kty":"OKP","use":"sig","x":"iRjI0Qr9WRzkvTcY4bv8tAGPgBGrj83PSikHxaRFKyM"}]}`,
		`{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`,
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
			if thumbprint, err := key.Thumbprint(); err == nil {
				_, _ = set.ByKid(thumbprint)
			}
		}
	})
}
