package envelope

import (
	"crypto/sha256"
	"encoding/binary"
)

// cekBits is the A256GCM content-encryption key length in bits (256 == one
// SHA-256 output block, so a single Concat KDF counter block suffices).
const cekBits = 256

// concatKDF derives keying material with the NIST SP 800-56A Concat KDF
// (SHA-256) as profiled for JWE ECDH-ES in RFC 7518 section 4.8.1: each
// counter block is SHA-256(counter || Z || OtherInfo) with counter a
// 4-byte big-endian running index starting at 1. OtherInfo concatenates
// the length-prefixed AlgorithmID, PartyUInfo, and PartyVInfo with the
// keydatalen as a 4-byte big-endian SuppPubInfo. Per the envelope
// contract, apu/apv are absent so both party-info fields contribute four
// zero bytes, and AlgorithmID is the enc algorithm name ("A256GCM").
//
// Parameters: z is the raw ECDH shared secret; algorithmID the content
// encryption algorithm name bytes; partyU/partyV the (empty) party info;
// keyBits the derived key length in bits (a positive multiple of 8).
// Returns: keyBits/8 bytes of derived keying material.
func concatKDF(z, algorithmID, partyU, partyV []byte, keyBits int) []byte {
	otherInfo := lenPrefixed(algorithmID)
	otherInfo = append(otherInfo, lenPrefixed(partyU)...)
	otherInfo = append(otherInfo, lenPrefixed(partyV)...)
	var keyLen [4]byte
	binary.BigEndian.PutUint32(keyLen[:], uint32(keyBits))
	otherInfo = append(otherInfo, keyLen[:]...)

	want := keyBits / 8
	out := make([]byte, 0, want+sha256.Size)
	for counter := uint32(1); len(out) < want; counter++ {
		var block [4]byte
		binary.BigEndian.PutUint32(block[:], counter)
		h := sha256.New()
		_, _ = h.Write(block[:])
		_, _ = h.Write(z)
		_, _ = h.Write(otherInfo)
		out = h.Sum(out)
	}
	return out[:want]
}

// lenPrefixed encodes one Concat KDF component as a 4-byte big-endian
// length followed by the value; an empty value encodes as four zero bytes.
func lenPrefixed(v []byte) []byte {
	out := make([]byte, 4, 4+len(v))
	binary.BigEndian.PutUint32(out, uint32(len(v)))
	return append(out, v...)
}
