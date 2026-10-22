package gatewaytest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/konsulin-care/gateway-sdk-go/internal/jwk"
	"github.com/konsulin-care/gateway-sdk-go/internal/jws"
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
