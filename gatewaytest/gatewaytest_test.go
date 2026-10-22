package gatewaytest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/konsulin-care/gateway-sdk-go/auth"
	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
	"github.com/konsulin-care/gateway-sdk-go/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goldenFiles is the explicit PRD §11 allow-list of the 12 mirrored golden
// vectors. The mirror script copies exactly these files — never a glob.
var goldenFiles = []string{
	"gateway-jwks.json",
	"ks-access.json",
	"ks-approval.json",
	"ks-delivery.json",
	"ks-event-service-result.json",
	"ks-party.json",
	"ks-result.json",
	"settlement-expired-buyer.json",
	"settlement-expired-provider.json",
	"settlement-paid-buyer.json",
	"settlement-paid-provider.json",
	"testonly-party-private.key",
}

// Paths relative to this package's directory (the working directory of
// `go test` for this package).
const (
	goldenDir    = "../testdata/golden"
	gatewayDir   = "../../gateway/testdata/golden"
	mirrorScript = "../scripts/mirror-golden.sh"
	repoRoot     = ".."
)

// signingKeyName is the gateway signing key that must never be mirrored.
const signingKeyName = "testonly-gateway-signing-private.key"

// TestGoldenMirrorPRD11FilesLoad asserts that all 12 PRD §11 files exist
// under testdata/golden/, are non-empty, and that the JSON vectors parse.
func TestGoldenMirrorPRD11FilesLoad(t *testing.T) {
	for _, name := range goldenFiles {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(goldenDir, name))
			require.NoError(t, err, "mirrored file must exist under %s", goldenDir)
			require.NotEmpty(t, data, "mirrored file must not be empty")

			if strings.HasSuffix(name, ".json") {
				var doc map[string]any
				require.NoError(t, json.Unmarshal(data, &doc), "JSON vector must parse")
				require.NotEmpty(t, doc, "JSON vector must not be empty")
			}
		})
	}
}

// TestGoldenMirrorByteIdenticalToGateway asserts that every mirrored file is
// byte-identical to the gateway original. Skips when the local gateway
// checkout is unavailable (the mirror itself is a local, offline operation).
func TestGoldenMirrorByteIdenticalToGateway(t *testing.T) {
	if _, err := os.Stat(gatewayDir); err != nil {
		t.Skipf("gateway checkout not available at %s; skipping byte-identity check", gatewayDir)
	}
	for _, name := range goldenFiles {
		t.Run(name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join(gatewayDir, name))
			require.NoError(t, err, "gateway original must exist")
			got, err := os.ReadFile(filepath.Join(goldenDir, name))
			require.NoError(t, err, "mirrored file must exist")
			assert.True(t, bytes.Equal(want, got),
				"%s must be byte-identical to the gateway original", name)
		})
	}
}

// TestGoldenMirrorGatewaySigningKeyAbsent asserts that the gateway signing
// key never appears anywhere in this repository.
func TestGoldenMirrorGatewaySigningKeyAbsent(t *testing.T) {
	err := filepath.WalkDir(repoRoot, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if filepath.Base(path) == signingKeyName {
			t.Errorf("gateway signing key must never be mirrored, found %s", path)
		}
		return nil
	})
	require.NoError(t, err, "repo walk must succeed")
}

// TestMirrorScriptExplicitAllowList asserts that scripts/mirror-golden.sh
// exists, is executable, copies only the explicit allow-list (no glob
// characters anywhere in the script), and names every PRD §11 file.
func TestMirrorScriptExplicitAllowList(t *testing.T) {
	info, err := os.Stat(mirrorScript)
	require.NoError(t, err, "mirror script must exist")
	assert.NotZero(t, info.Mode()&0o111, "mirror script must be executable")

	script, err := os.ReadFile(mirrorScript)
	require.NoError(t, err)
	content := string(script)

	assert.NotContains(t, content, "*", "mirror script must use an explicit allow-list, never a glob")
	for _, name := range goldenFiles {
		assert.Contains(t, content, name, "mirror script must list %s explicitly", name)
	}
}

// TestGitignoreUnignoresOnlyPartyKey asserts that .gitignore un-ignores only
// testdata/golden/testonly-party-private.key and that every other *.key and
// *.pem stays ignored.
func TestGitignoreUnignoresOnlyPartyKey(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".gitignore"))
	require.NoError(t, err)

	var keyUnignores []string
	ignoredKeys := false
	ignoredPEMs := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "*.key":
			ignoredKeys = true
		case line == "*.pem":
			ignoredPEMs = true
		case strings.HasPrefix(line, "!") && strings.HasSuffix(line, ".key"):
			keyUnignores = append(keyUnignores, line)
		}
	}
	assert.True(t, ignoredKeys, "*.key must stay ignored")
	assert.True(t, ignoredPEMs, "*.pem must stay ignored")
	assert.Equal(t, []string{"!testdata/golden/testonly-party-private.key"}, keyUnignores,
		"the only key un-ignore must be testdata/golden/testonly-party-private.key")
}

// tokenVector reports whether the golden file is a token vector carrying a
// "claims" object (the JSON vectors except the JWKS document).
func tokenVector(name string) bool {
	return strings.HasSuffix(name, ".json") && name != "gateway-jwks.json"
}

// TestFixtureLoaderReturnsEveryMirroredFixture asserts that the fixture
// loader returns every PRD §11 fixture by name, with the exact mirrored
// bytes and, for token vectors, the parsed claims object.
func TestFixtureLoaderReturnsEveryMirroredFixture(t *testing.T) {
	fixtures, err := LoadFixtures(goldenDir)
	require.NoError(t, err, "mirrored golden set must load")
	require.Len(t, fixtures, len(goldenFiles), "every allow-listed fixture must be returned")

	for _, name := range goldenFiles {
		t.Run(name, func(t *testing.T) {
			got, ok := fixtures[name]
			require.True(t, ok, "fixture %s must be returned by name", name)
			assert.Equal(t, name, got.Name)

			wantData, err := os.ReadFile(filepath.Join(goldenDir, name))
			require.NoError(t, err)
			assert.True(t, bytes.Equal(wantData, got.Data),
				"fixture %s must carry the exact mirrored bytes", name)

			if tokenVector(name) {
				var doc struct {
					Claims map[string]any `json:"claims"`
				}
				require.NoError(t, json.Unmarshal(wantData, &doc))
				require.NotNil(t, doc.Claims)
				assert.Equal(t, doc.Claims, got.Claims,
					"fixture %s must expose its parsed claims", name)
			}
		})
	}
}

// TestFixtureLoaderRejectsGatewaySigningKey asserts that loading a
// directory containing testonly-gateway-signing-private.key fails closed
// even when the rest of the mirrored set is intact.
func TestFixtureLoaderRejectsGatewaySigningKey(t *testing.T) {
	dir := t.TempDir()
	for _, name := range goldenFiles {
		data, err := os.ReadFile(filepath.Join(goldenDir, name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o600))
	}

	_, err := LoadFixtures(dir)
	require.NoError(t, err, "the copied golden set must load before the key is planted")

	require.NoError(t, os.WriteFile(filepath.Join(dir, signingKeyName), []byte("test key"), 0o600))

	fixtures, err := LoadFixtures(dir)
	require.Error(t, err, "a directory containing the gateway signing key must fail to load")
	assert.Nil(t, fixtures, "no fixtures must be returned when the load fails")
	assert.Contains(t, err.Error(), signingKeyName,
		"the error must name the offending file")
}

// ed25519Thumbprint returns the RFC 7638 thumbprint of an Ed25519 public key:
// the kid a token signed by that key must carry.
func ed25519Thumbprint(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	raw, err := json.Marshal(map[string]string{
		"crv": "Ed25519",
		"kty": "OKP",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	})
	require.NoError(t, err)
	kid, err := jwk.Thumbprint(raw)
	require.NoError(t, err)
	return kid
}

// TestFakeJWKSServerServesValidJWKS asserts that a GET on the served JWKS
// URL returns the exact served document and that its keys validate with the
// jwk package: every key parses and carries its RFC 7638 thumbprint as kid.
func TestFakeJWKSServerServesValidJWKS(t *testing.T) {
	fixtures, err := LoadFixtures(goldenDir)
	require.NoError(t, err)
	served := fixtures["gateway-jwks.json"].Data

	srv, err := NewJWKSServer(served)
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL())
	require.NoError(t, err, "the fake server is a local httptest listener")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(served, body),
		"GET must return the served JWKS byte-exact")

	keys, err := jwk.ParseJWKS(body)
	require.NoError(t, err, "served keys must validate with the jwk package")
	require.NotEmpty(t, keys.Keys)
	for _, key := range keys.Keys {
		kid, err := key.Thumbprint()
		require.NoError(t, err)
		assert.Equal(t, kid, key.Kid,
			"every served kid must be the key's RFC 7638 thumbprint")
	}
}

// TestFakeJWKSServerRejectsInvalidJWKS asserts that a malformed document
// fails closed at construction with no server started.
func TestFakeJWKSServerRejectsInvalidJWKS(t *testing.T) {
	srv, err := NewJWKSServer([]byte(`{"keys":"nope"}`))
	require.Error(t, err, "a malformed JWKS must fail at construction")
	assert.Nil(t, srv, "no server must be returned on error")
}

// TestFakeJWKSServerKidOnlyVerify asserts that the fake verify path selects
// the key by the token's own kid only: a token signed by the served key is
// accepted and yields its payload, a token signed with an unknown kid is
// denied before any signature check, and a served kid carrying a foreign
// signature is denied by the Ed25519 verification.
func TestFakeJWKSServerKidOnlyVerify(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwksData, err := Ed25519JWKS(pubA)
	require.NoError(t, err)
	srv, err := NewJWKSServer(jwksData)
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	keys, err := jwk.ParseJWKS(jwksData)
	require.NoError(t, err)
	require.Len(t, keys.Keys, 1)
	kidA := ed25519Thumbprint(t, pubA)
	kidB := ed25519Thumbprint(t, pubB)
	assert.Equal(t, kidA, keys.Keys[0].Kid,
		"the served kid must be the RFC 7638 thumbprint of the served key")
	assert.NotEqual(t, kidA, kidB, "distinct keys have distinct thumbprints")

	payload := []byte(`{"sub":"gateway-verify-path"}`)
	good, err := jws.SignEd25519(privA,
		jws.Header{Alg: jws.AlgEdDSA, Kid: kidA, Typ: "ks-party+jwt"}, payload)
	require.NoError(t, err)
	got, err := srv.Verify(good)
	require.NoError(t, err, "a token signed by the served key must verify")
	assert.Equal(t, payload, got, "Verify must return the verified payload")

	unknown, err := jws.SignEd25519(privB,
		jws.Header{Alg: jws.AlgEdDSA, Kid: kidB, Typ: "ks-party+jwt"}, payload)
	require.NoError(t, err)
	_, err = srv.Verify(unknown)
	require.Error(t, err, "a token signed with an unknown kid must be denied")
	assert.Contains(t, err.Error(), "unknown kid")

	forged, err := jws.SignEd25519(privB,
		jws.Header{Alg: jws.AlgEdDSA, Kid: kidA, Typ: "ks-party+jwt"}, payload)
	require.NoError(t, err)
	_, err = srv.Verify(forged)
	require.Error(t, err, "a served kid with a foreign signature must be denied")
	assert.Contains(t, err.Error(), "signature")
}

// TestMinterMintsEdDSATokenAcceptedByFakeJWKS asserts that a token minted
// with the minter's generated Ed25519 test key verifies against the fake
// JWKS server through the EdDSA path: exact typ, alg EdDSA, kid = the RFC
// 7638 thumbprint of the minter key, and the payload round trip.
func TestMinterMintsEdDSATokenAcceptedByFakeJWKS(t *testing.T) {
	m, err := NewMinter()
	require.NoError(t, err)

	jwksData, err := m.JWKS()
	require.NoError(t, err)
	srv, err := NewJWKSServer(jwksData)
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	payload := []byte(`{"sub":"minter"}`)
	tok, err := m.Mint(wire.TypParty, payload)
	require.NoError(t, err)

	hdr, parsed, _, err := jws.Parse([]byte(tok))
	require.NoError(t, err)
	assert.Equal(t, wire.TypParty, hdr.Typ)
	assert.Equal(t, jws.AlgEdDSA, hdr.Alg)
	assert.Equal(t, m.Kid(), hdr.Kid)
	assert.Equal(t, ed25519Thumbprint(t, m.PublicKey()), hdr.Kid,
		"the kid must be the RFC 7638 thumbprint of the minter key")

	got, err := srv.Verify(tok)
	require.NoError(t, err, "a minted token must verify against the fake JWKS on the EdDSA path")
	assert.Equal(t, payload, got)
	assert.Equal(t, parsed, got)
}

// TestMinterES256RequiresExplicitOptIn asserts that ES256 minting is
// reachable only through the explicit opt-in key type: the default minter
// path has no algorithm input and always produces EdDSA for every typ, a
// zero-value opt-in key is rejected with no token, and only the explicit
// opt-in call yields an ES256 token — which every default EdDSA path then
// denies.
func TestMinterES256RequiresExplicitOptIn(t *testing.T) {
	m, err := NewMinter()
	require.NoError(t, err)
	jwksData, err := m.JWKS()
	require.NoError(t, err)
	srv, err := NewJWKSServer(jwksData)
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	payload := []byte(`{"sub":"minter"}`)

	// The default path never produces ES256 — for any of the six typs.
	for _, typ := range wire.Typs() {
		tok, err := m.Mint(typ, payload)
		require.NoError(t, err, "mint %s", typ)
		hdr, _, _, err := jws.Parse([]byte(tok))
		require.NoError(t, err)
		assert.Equal(t, jws.AlgEdDSA, hdr.Alg, "mint %s must be EdDSA", typ)
	}

	// Minting an ES256 token without the explicit opt-in is not possible:
	// the zero-value key is rejected and no token is returned.
	tok, err := MintES256(auth.ES256Key{}, payload)
	require.Error(t, err, "ES256 minting without the explicit opt-in must be impossible")
	assert.Contains(t, err.Error(), "opt-in")
	assert.Empty(t, tok)

	// The explicit opt-in produces an ES256 ks-party+jwt token.
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tok, err = MintES256(auth.ES256Key{Private: ecPriv}, payload)
	require.NoError(t, err)
	hdr, _, _, err := jws.Parse([]byte(tok))
	require.NoError(t, err)
	assert.Equal(t, wire.TypParty, hdr.Typ)
	assert.Equal(t, jws.AlgES256, hdr.Alg)

	// Every default EdDSA path denies it: the token-kind allow-list ...
	require.Error(t, jws.CheckKind(hdr, wire.TypParty))
	require.Error(t, jws.CheckKindParty(hdr, wire.TypParty, jws.PartyEdDSA))
	// ... the fake JWKS server (EdDSA-only, kid-only selection) ...
	_, err = srv.Verify(tok)
	require.Error(t, err, "the fake verify path must deny an ES256 token")
	// ... and a direct Ed25519 verify against the minter key.
	_, _, err = jws.VerifyEd25519(m.PublicKey(), []byte(tok))
	require.Error(t, err)

	// Only the explicit opt-in verification path accepts it.
	gotHdr, gotPayload, err := jws.VerifyES256(&ecPriv.PublicKey, []byte(tok))
	require.NoError(t, err)
	require.NoError(t, jws.CheckKindParty(gotHdr, wire.TypParty, jws.PartyES256))
	assert.Equal(t, payload, gotPayload)
}

// TestReplayCacheFirstAcceptedThenReplay asserts that the first Check of a
// (scope, key) pair is accepted and every later Check of the same pair is a
// replay, with the verdict unchanged across repeated calls.
func TestReplayCacheFirstAcceptedThenReplay(t *testing.T) {
	c := NewReplayCache()
	require.NotNil(t, c, "a new ReplayCache must be ready to use")

	const key = "replay-key-0001"
	assert.True(t, c.Check(ReplayScopeJTI, key),
		"the first Check of a key must be accepted")
	assert.False(t, c.Check(ReplayScopeJTI, key),
		"the second Check of the same key must be a replay")
	for i := 0; i < 5; i++ {
		assert.False(t, c.Check(ReplayScopeJTI, key),
			"the verdict must not change across repeated calls with the same key")
	}
}

// TestReplayCacheScopesAreIndependent asserts that the jti and webhook_id
// scopes are separate key spaces: the same raw key in a different scope is
// a distinct entry, so a webhook_id never collides with a jti.
func TestReplayCacheScopesAreIndependent(t *testing.T) {
	c := NewReplayCache()

	const key = "shared-key-material"
	assert.True(t, c.Check(ReplayScopeJTI, key), "fresh jti must be accepted")
	assert.True(t, c.Check(ReplayScopeWebhookID, key),
		"the same key under the webhook_id scope is a distinct entry")
	assert.False(t, c.Check(ReplayScopeWebhookID, key),
		"the webhook_id entry must now be a replay")
	assert.False(t, c.Check(ReplayScopeJTI, key),
		"the jti entry must still be a replay")
}

// TestReplayCacheDeterministicWithoutClock asserts the verdict depends only
// on the history of Check calls, never on wall-clock time: two caches driven
// by the same sequence of calls yield identical verdicts.
func TestReplayCacheDeterministicWithoutClock(t *testing.T) {
	sequence := []struct {
		scope string
		key   string
	}{
		{ReplayScopeJTI, "jti-alpha"},
		{ReplayScopeWebhookID, "whid-alpha"},
		{ReplayScopeJTI, "jti-alpha"},
		{ReplayScopeWebhookID, "whid-alpha"},
		{ReplayScopeJTI, "jti-beta"},
		{ReplayScopeJTI, "jti-beta"},
	}
	run := func() []bool {
		c := NewReplayCache()
		verdicts := make([]bool, 0, len(sequence))
		for _, s := range sequence {
			verdicts = append(verdicts, c.Check(s.scope, s.key))
		}
		return verdicts
	}
	assert.Equal(t, []bool{true, true, false, false, true, false}, run(),
		"first observation accepted, every repeat a replay")
	assert.Equal(t, run(), run(),
		"verdicts must be identical across independent runs: no clock input")
}

// TestReplayCacheConcurrentSingleWinner asserts that lookup-and-insert is
// atomic per key under concurrent use: of many simultaneous Checks of one
// key exactly one is accepted.
func TestReplayCacheConcurrentSingleWinner(t *testing.T) {
	c := NewReplayCache()
	const n = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = c.Check(ReplayScopeJTI, "concurrent-key")
		}(i)
	}
	close(start)
	wg.Wait()

	accepted := 0
	for _, r := range results {
		if r {
			accepted++
		}
	}
	assert.Equal(t, 1, accepted,
		"exactly one concurrent Check of the same key must be accepted")
}
