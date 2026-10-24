package envelope

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

// fuzzSeedPayload is the plaintext of the valid FuzzOpen seed envelope.
const fuzzSeedPayload = "fuzz seed payload"

// FuzzOpen asserts SDK-ENV-C01's fuzz clause: Open never panics on
// arbitrary input and never returns plaintext for a rejected envelope.
// Seeds cover a valid sealed token plus malformed shapes (wrong segment
// counts, non-base64 segments, garbage); the fuzzer mutates beyond them.
// A successful open is only ever accepted for the exact seed payload —
// any other success would mean authentication was bypassed.
func FuzzOpen(f *testing.F) {
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("envelope: fuzz: recipient key: %v", err)
	}
	sealed, err := Seal([]byte(fuzzSeedPayload), "fuzz-kid", recipient.PublicKey())
	if err != nil {
		f.Fatalf("envelope: fuzz: seed seal: %v", err)
	}

	seeds := []string{
		sealed,
		sealed[:len(sealed)/2], // truncated token
		"",
		".",
		"..",
		"...",
		"....",
		"a.b.c.d.e",
		"@@@.e...e.e",
		"not-an-envelope",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, compact string) {
		plaintext, err := Open(compact, recipient)
		if err != nil {
			if plaintext != nil {
				t.Fatalf("Open rejected the input but returned %d bytes of plaintext",
					len(plaintext))
			}
			return
		}
		if string(plaintext) != fuzzSeedPayload {
			t.Fatalf("Open accepted a fuzzed input and returned unexpected plaintext (%d bytes)",
				len(plaintext))
		}
	})
}
