package gatewaytest

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Paths relative to this package's directory (the working directory of
// `go test` for this package).
const (
	goldenDir = "../testdata/golden"
	repoRoot  = ".."
)

// TestGoldenMirrorPRD11FilesLoad asserts that all 12 PRD §11 files exist
// under testdata/golden/, are non-empty, and that the JSON vectors parse.
func TestGoldenMirrorPRD11FilesLoad(t *testing.T) {
	for _, name := range goldenNames {
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

// TestGoldenMirrorGatewaySigningKeyAbsent asserts that the gateway signing
// key never appears anywhere in this repository.
func TestGoldenMirrorGatewaySigningKeyAbsent(t *testing.T) {
	err := filepath.WalkDir(repoRoot, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if filepath.Base(path) == gatewaySigningKeyName {
			t.Errorf("gateway signing key must never be mirrored, found %s", path)
		}
		return nil
	})
	require.NoError(t, err, "repo walk must succeed")
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
