package gatewaytest

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// goldenNames is the explicit PRD §11 allow-list of the 12 mirrored golden
// vectors. The fixture loader loads exactly these files — never a glob.
var goldenNames = []string{
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

// gatewaySigningKeyName is the gateway's own signing key. It must never be
// mirrored; loading a fixture directory that contains it fails closed.
const gatewaySigningKeyName = "testonly-gateway-signing-private.key"

// Fixture is one mirrored golden vector: its file name, the exact mirrored
// bytes, and the parsed claims object for token vectors (Claims is nil for
// the JWKS document and the party key file).
type Fixture struct {
	// Name is the fixture's file name, e.g. "ks-party.json".
	Name string
	// Data is the exact mirrored file bytes.
	Data []byte
	// Claims is the parsed "claims" object of a token vector; nil otherwise.
	Claims map[string]any
}

// LoadFixtures loads the mirrored PRD §11 golden set from dir and returns
// every fixture keyed by file name. It fails closed: an error is returned
// and no fixtures are returned if any allow-listed file is missing or
// malformed, a token vector lacks a claims object, or the gateway signing
// key (testonly-gateway-signing-private.key) appears anywhere under dir.
//
// Parameter dir is the fixture directory (e.g. "testdata/golden").
// The return value is the fixtures keyed by file name, and an error.
func LoadFixtures(dir string) (map[string]Fixture, error) {
	if err := rejectGatewaySigningKey(dir); err != nil {
		return nil, err
	}
	fixtures := make(map[string]Fixture, len(goldenNames))
	for _, name := range goldenNames {
		f, err := loadFixture(dir, name)
		if err != nil {
			return nil, err
		}
		fixtures[name] = f
	}
	return fixtures, nil
}

// loadFixture reads and parses one allow-listed golden file from dir.
// Token vectors must carry a non-empty claims object; other fixtures must
// parse as JSON where applicable, with Claims left nil.
func loadFixture(dir, name string) (Fixture, error) {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return Fixture{}, fmt.Errorf("gatewaytest: load golden %s: %w", name, err)
	}
	f := Fixture{Name: name, Data: data}
	if !strings.HasSuffix(name, ".json") {
		return f, nil
	}
	var doc struct {
		Claims map[string]any `json:"claims"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return Fixture{}, fmt.Errorf("gatewaytest: parse golden %s: %w", name, err)
	}
	if tokenVectorName(name) && doc.Claims == nil {
		return Fixture{}, fmt.Errorf("gatewaytest: golden %s: missing claims object", name)
	}
	f.Claims = doc.Claims
	return f, nil
}

// tokenVectorName reports whether the allow-listed golden file is a token
// vector carrying a claims object (the JSON vectors except the JWKS doc).
func tokenVectorName(name string) bool {
	return strings.HasSuffix(name, ".json") && name != "gateway-jwks.json"
}

// rejectGatewaySigningKey walks dir and returns an error naming the file if
// the gateway signing key appears anywhere under it.
func rejectGatewaySigningKey(dir string) error {
	found := ""
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == gatewaySigningKeyName {
			found = path
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("gatewaytest: scan fixture dir %s: %w", dir, err)
	}
	if found != "" {
		return fmt.Errorf("gatewaytest: refusing to load %s: gateway signing key %s must never be mirrored",
			dir, gatewaySigningKeyName)
	}
	return nil
}
