package gatewaytest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// copyGoldenWithManifest copies the committed golden set and MANIFEST.json
// into a fresh temp dir and asserts the copy verifies, so every tamper
// scenario starts from the accepted committed state.
func copyGoldenWithManifest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range append([]string{manifestFileName}, goldenNames...) {
		data, err := os.ReadFile(filepath.Join(goldenDir, name))
		require.NoError(t, err, "committed %s must exist", name)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o600))
	}
	require.NoError(t, VerifyManifest(dir),
		"the copied committed set must verify before any tampering")
	return dir
}

// rewriteManifest loads the manifest from dir, applies mutate, and writes
// the result back.
func rewriteManifest(t *testing.T, dir string, mutate func(*Manifest)) {
	t.Helper()
	m, err := LoadManifest(dir)
	require.NoError(t, err)
	mutate(&m)
	raw, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, manifestFileName), raw, 0o600))
}

// TestGoldenManifestMatchesCommittedSet asserts that the committed
// MANIFEST.json records the gateway source commit and a SHA-256 for each
// of the 12 allow-listed vectors — exactly the goldenNames set — that every
// recorded hash equals the hash of the committed file, and that
// VerifyManifest accepts the committed set offline (no gateway checkout).
func TestGoldenManifestMatchesCommittedSet(t *testing.T) {
	manifest, err := LoadManifest(goldenDir)
	require.NoError(t, err, "the committed manifest must load")
	assert.Len(t, manifest.GatewayCommit, 40,
		"the manifest must record the 40-character gateway source commit")

	names := make([]string, 0, len(manifest.Files))
	for name := range manifest.Files {
		names = append(names, name)
	}
	assert.ElementsMatch(t, goldenNames, names,
		"the manifest file list must equal the goldenNames allow-list")

	for _, name := range goldenNames {
		sum, ok := manifest.Files[name]
		require.True(t, ok, "the manifest must list %s", name)
		data, err := os.ReadFile(filepath.Join(goldenDir, name))
		require.NoError(t, err)
		hash := sha256.Sum256(data)
		assert.Equal(t, hex.EncodeToString(hash[:]), sum,
			"the manifest hash of %s must equal the committed file's SHA-256", name)
	}

	require.NoError(t, VerifyManifest(goldenDir),
		"the committed set must verify with no gateway checkout present")
}

// TestGoldenManifestFailsClosedOnHashMismatch asserts that a golden file
// whose bytes drift from the manifest entry is denied with the named
// ErrManifestHashMismatch error naming the file.
func TestGoldenManifestFailsClosedOnHashMismatch(t *testing.T) {
	dir := copyGoldenWithManifest(t)
	data, err := os.ReadFile(filepath.Join(dir, "ks-access.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ks-access.json"),
		append(data, ' '), 0o600))

	err = VerifyManifest(dir)
	require.Error(t, err, "a hash mismatch must fail closed")
	assert.ErrorIs(t, err, ErrManifestHashMismatch,
		"the failure must be the named ErrManifestHashMismatch error")
	assert.Contains(t, err.Error(), "ks-access.json",
		"the error must name the offending file")
}

// TestGoldenManifestFailsClosedOnMissingEntry asserts that an allow-listed
// file with no manifest entry is denied with the named
// ErrManifestMissingEntry error naming the file.
func TestGoldenManifestFailsClosedOnMissingEntry(t *testing.T) {
	dir := copyGoldenWithManifest(t)
	rewriteManifest(t, dir, func(m *Manifest) { delete(m.Files, "ks-party.json") })

	err := VerifyManifest(dir)
	require.Error(t, err, "a missing manifest entry must fail closed")
	assert.ErrorIs(t, err, ErrManifestMissingEntry,
		"the failure must be the named ErrManifestMissingEntry error")
	assert.Contains(t, err.Error(), "ks-party.json",
		"the error must name the missing file")
}

// TestGoldenManifestFailsClosedOnFileAbsentFromManifest asserts that a
// vector file present on disk but absent from the manifest is denied with
// the named ErrManifestUnexpectedFile error naming the file.
func TestGoldenManifestFailsClosedOnFileAbsentFromManifest(t *testing.T) {
	dir := copyGoldenWithManifest(t)
	require.NoError(t,
		os.WriteFile(filepath.Join(dir, "ks-extra.json"), []byte("{}"), 0o600))

	err := VerifyManifest(dir)
	require.Error(t, err, "an unlisted file on disk must fail closed")
	assert.ErrorIs(t, err, ErrManifestUnexpectedFile,
		"the failure must be the named ErrManifestUnexpectedFile error")
	assert.Contains(t, err.Error(), "ks-extra.json",
		"the error must name the offending file")
}

// TestGoldenManifestRejectsUnknownManifestEntry asserts that a manifest
// entry outside the goldenNames allow-list is denied, so the manifest file
// list can only ever equal the allow-list.
func TestGoldenManifestRejectsUnknownManifestEntry(t *testing.T) {
	dir := copyGoldenWithManifest(t)
	rewriteManifest(t, dir, func(m *Manifest) {
		m.Files["not-a-vector.json"] = strings.Repeat("a", 64)
	})

	err := VerifyManifest(dir)
	require.Error(t, err, "a manifest entry outside the allow-list must fail closed")
	assert.ErrorIs(t, err, ErrManifestUnexpectedEntry,
		"the failure must be the named ErrManifestUnexpectedEntry error")
	assert.Contains(t, err.Error(), "not-a-vector.json",
		"the error must name the offending entry")
}

// TestGoldenManifestFailsClosedWithoutManifestFile asserts that a golden
// directory without MANIFEST.json fails closed rather than accepting the
// unhashed files.
func TestGoldenManifestFailsClosedWithoutManifestFile(t *testing.T) {
	dir := copyGoldenWithManifest(t)
	require.NoError(t, os.Remove(filepath.Join(dir, manifestFileName)))

	err := VerifyManifest(dir)
	require.Error(t, err, "a missing manifest must fail closed")
	assert.Contains(t, err.Error(), manifestFileName,
		"the error must name the missing manifest")
}

// TestGoldenManifestRejectsMalformedManifest asserts that structural
// violations of MANIFEST.json — a gateway commit that is not a 40-character
// hex sha, and an entry hash that is not a 64-character hex sha — fail
// closed before any golden file is hashed.
func TestGoldenManifestRejectsMalformedManifest(t *testing.T) {
	t.Run("commit", func(t *testing.T) {
		dir := copyGoldenWithManifest(t)
		rewriteManifest(t, dir, func(m *Manifest) { m.GatewayCommit = "deadbeef" })
		err := VerifyManifest(dir)
		require.Error(t, err, "a non-hex gateway commit must fail closed")
		assert.Contains(t, err.Error(), "gateway_commit",
			"the error must name the offending field")
	})
	t.Run("hash", func(t *testing.T) {
		dir := copyGoldenWithManifest(t)
		rewriteManifest(t, dir, func(m *Manifest) {
			m.Files["ks-access.json"] = "not-hex"
		})
		err := VerifyManifest(dir)
		require.Error(t, err, "a malformed sha256 entry must fail closed")
		assert.Contains(t, err.Error(), "ks-access.json",
			"the error must name the offending entry")
	})
}
