package gatewaytest

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
