package wire

// EnrollPartyRequest is the POST /v1/parties/{id}/enroll body: the
// single-use enrollment token plus proof-of-possession key material.
// Fields map byte-exact to the Bruno example (parties/enroll-party.yml).
type EnrollPartyRequest struct {
	// EnrollmentToken is the single-use token issued by the operator.
	EnrollmentToken string `json:"enrollment_token"`
	// PublicKey is the base64 StdEncoding public key being registered.
	PublicKey string `json:"public_key"`
	// Kid is the key id stored with the new key row.
	Kid string `json:"kid"`
	// Alg is optional: "Ed25519" (gateway default) or "ES256".
	Alg string `json:"alg,omitempty"`
	// EncPublicKey is the optional base64 X25519 public key published
	// as the party's use:enc JWKS entry.
	EncPublicKey string `json:"enc_public_key,omitempty"`
}

// EnrollPartyResponse is the 200 body of POST /v1/parties/{id}/enroll:
// the party is active and its key is stored.
type EnrollPartyResponse struct {
	// PartyID is the enrolled party's id.
	PartyID string `json:"party_id"`
	// Kid is the stored key id.
	Kid string `json:"kid"`
}

// RotateKeyRequest is the POST /v1/parties/{id}/keys body: the new key
// material, signed for by the party's current active key.
type RotateKeyRequest struct {
	// PublicKey is the new base64 StdEncoding public key.
	PublicKey string `json:"public_key"`
	// Kid is the new key id (globally unique).
	Kid string `json:"kid"`
	// Alg is optional: "Ed25519" (gateway default) or "ES256".
	Alg string `json:"alg,omitempty"`
}

// RotateKeyResponse is the 200 body of POST /v1/parties/{id}/keys.
type RotateKeyResponse struct {
	// Kid is the newly installed key id.
	Kid string `json:"kid"`
}

// JWK is one key of a served JWK Set (RFC 7517) as the gateway emits
// it: OKP/EC signature keys carry kty/crv/kid/x/alg/use, EC keys add y,
// and X25519 encryption entries carry no alg member.
type JWK struct {
	// Kty is the key type ("OKP" or "EC").
	Kty string `json:"kty"`
	// Crv is the curve ("Ed25519", "X25519", "P-256").
	Crv string `json:"crv"`
	// Kid is the key id (RFC 7638 thumbprint for gateway keys).
	Kid string `json:"kid"`
	// X is the base64url (unpadded) public coordinate.
	X string `json:"x"`
	// Y is the second EC coordinate; absent for OKP keys.
	Y string `json:"y,omitempty"`
	// Alg is the JWS algorithm; absent on use:enc entries.
	Alg string `json:"alg,omitempty"`
	// Use is "sig" or "enc".
	Use string `json:"use"`
}

// JWKSResponse is the body of GET /v1/parties/{id}/jwks and
// GET /.well-known/jwks: an RFC 7517 key set.
type JWKSResponse struct {
	// Keys holds every currently-valid key (oldest first for parties).
	Keys []JWK `json:"keys"`
}

// PartyHealthResponse is the 200 body of GET /v1/parties/{id}/health.
type PartyHealthResponse struct {
	// Status is "healthy" when the gateway's probe returned 2xx.
	Status string `json:"status"`
}

// GatewayHealthResponse is the 200 body of GET /health (meta/health.yml).
type GatewayHealthResponse struct {
	// Status is "ok" while the process is serving.
	Status string `json:"status"`
	// Version is the gateway build version.
	Version string `json:"version"`
}
