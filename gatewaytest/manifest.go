package gatewaytest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// manifestFileName is the name of the golden manifest inside a fixture
// directory: one SHA-256 entry per allow-listed vector plus the gateway
// source commit the vectors were mirrored from.
const manifestFileName = "MANIFEST.json"

// Manifest is the parsed golden manifest: the gateway source commit the
// vectors were mirrored from, and the SHA-256 of each allow-listed file.
type Manifest struct {
	// GatewayCommit is the full 40-character lowercase hex git commit of
	// the gateway checkout the mirrored vectors were copied from.
	GatewayCommit string `json:"gateway_commit"`
	// Files maps each allow-listed file name to its 64-character lowercase
	// hex SHA-256 over the exact mirrored bytes.
	Files map[string]string `json:"files"`
}

// ErrManifestMissingEntry reports that the manifest has no entry for an
// allow-listed golden file.
var ErrManifestMissingEntry = errors.New("gatewaytest: manifest entry missing")

// ErrManifestHashMismatch reports that a golden file's SHA-256 differs
// from its manifest entry.
var ErrManifestHashMismatch = errors.New("gatewaytest: golden file hash mismatch")

// ErrManifestUnexpectedEntry reports that the manifest lists a file that
// is not in the goldenNames allow-list.
var ErrManifestUnexpectedEntry = errors.New("gatewaytest: manifest entry not in allow-list")

// ErrManifestUnexpectedFile reports that a vector file present on disk has
// no manifest entry.
var ErrManifestUnexpectedFile = errors.New("gatewaytest: golden file absent from manifest")

// LoadManifest reads and parses dir/MANIFEST.json and validates its
// structure: a 40-character lowercase hex gateway commit, at least one
// entry, entry keys that are bare file names, and 64-character lowercase
// hex SHA-256 values. It fails closed on any violation.
//
// Parameter dir is the fixture directory (e.g. "testdata/golden").
// The return value is the parsed manifest, and an error.
func LoadManifest(dir string) (Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, manifestFileName))
	if err != nil {
		return Manifest{}, fmt.Errorf("gatewaytest: load %s: %w", manifestFileName, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("gatewaytest: parse %s: %w", manifestFileName, err)
	}
	if !isHex(m.GatewayCommit, 40) {
		return Manifest{}, fmt.Errorf("gatewaytest: %s: gateway_commit must be a 40-character hex git commit, got %q",
			manifestFileName, m.GatewayCommit)
	}
	if len(m.Files) == 0 {
		return Manifest{}, fmt.Errorf("gatewaytest: %s: files must not be empty", manifestFileName)
	}
	for name, sum := range m.Files {
		if name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
			return Manifest{}, fmt.Errorf("gatewaytest: %s: entry %q must be a bare file name",
				manifestFileName, name)
		}
		if !isHex(sum, 64) {
			return Manifest{}, fmt.Errorf("gatewaytest: %s: entry %q must be a 64-character hex sha256, got %q",
				manifestFileName, name, sum)
		}
	}
	return m, nil
}

// VerifyManifest verifies the golden set in dir against dir/MANIFEST.json
// and fails closed. Every allow-listed file (goldenNames) must have a
// manifest entry whose SHA-256 equals the committed file's hash; the
// manifest must list nothing beyond the allow-list; and no vector file
// (*.json, *.key, *.pem, other than the manifest itself) may sit on disk
// without a manifest entry. Errors name the offending file:
// ErrManifestMissingEntry, ErrManifestHashMismatch, ErrManifestUnexpectedEntry,
// and ErrManifestUnexpectedFile respectively.
//
// Parameter dir is the fixture directory (e.g. "testdata/golden").
// The return value is nil when the committed set matches the manifest.
func VerifyManifest(dir string) error {
	m, err := LoadManifest(dir)
	if err != nil {
		return err
	}
	for _, name := range goldenNames {
		sum, ok := m.Files[name]
		if !ok {
			return fmt.Errorf("%w: %s", ErrManifestMissingEntry, name)
		}
		got, err := fileSHA256(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("gatewaytest: hash golden %s: %w", name, err)
		}
		if got != sum {
			return fmt.Errorf("%w: %s (manifest %s, disk %s)",
				ErrManifestHashMismatch, name, sum, got)
		}
	}
	for name := range m.Files {
		if !isGoldenName(name) {
			return fmt.Errorf("%w: %s", ErrManifestUnexpectedEntry, name)
		}
	}
	return verifyNoUnlistedFiles(dir, m.Files)
}

// verifyNoUnlistedFiles fails, naming the file, when a vector file in the
// flat golden directory has no manifest entry. The manifest itself and
// non-vector files (e.g. README.md) are ignored.
func verifyNoUnlistedFiles(dir string, files map[string]string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("gatewaytest: read golden dir %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == manifestFileName || !isVectorFileName(name) {
			continue
		}
		if _, ok := files[name]; !ok {
			return fmt.Errorf("%w: %s", ErrManifestUnexpectedFile, name)
		}
	}
	return nil
}

// isGoldenName reports whether name is in the goldenNames allow-list.
func isGoldenName(name string) bool {
	for _, n := range goldenNames {
		if n == name {
			return true
		}
	}
	return false
}

// isVectorFileName reports whether the file name marks a golden vector
// (a JSON vector or a key file) rather than documentation.
func isVectorFileName(name string) bool {
	return strings.HasSuffix(name, ".json") ||
		strings.HasSuffix(name, ".key") ||
		strings.HasSuffix(name, ".pem")
}

// fileSHA256 returns the lowercase hex SHA-256 of the file at path.
func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// isHex reports whether s is exactly n lowercase hexadecimal characters.
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
