package gatewaytest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFixtureLoaderReturnsEveryMirroredFixture asserts that the fixture
// loader returns every PRD §11 fixture by name, with the exact mirrored
// bytes and, for token vectors, the parsed claims object.
func TestFixtureLoaderReturnsEveryMirroredFixture(t *testing.T) {
	fixtures, err := LoadFixtures(goldenDir)
	require.NoError(t, err, "mirrored golden set must load")
	require.Len(t, fixtures, len(goldenNames), "every allow-listed fixture must be returned")

	for _, name := range goldenNames {
		t.Run(name, func(t *testing.T) {
			got, ok := fixtures[name]
			require.True(t, ok, "fixture %s must be returned by name", name)
			assert.Equal(t, name, got.Name)

			wantData, err := os.ReadFile(filepath.Join(goldenDir, name))
			require.NoError(t, err)
			assert.True(t, bytes.Equal(wantData, got.Data),
				"fixture %s must carry the exact mirrored bytes", name)

			if tokenVectorName(name) {
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
	for _, name := range goldenNames {
		data, err := os.ReadFile(filepath.Join(goldenDir, name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o600))
	}

	_, err := LoadFixtures(dir)
	require.NoError(t, err, "the copied golden set must load before the key is planted")

	require.NoError(t, os.WriteFile(filepath.Join(dir, gatewaySigningKeyName), []byte("test key"), 0o600))

	fixtures, err := LoadFixtures(dir)
	require.Error(t, err, "a directory containing the gateway signing key must fail to load")
	assert.Nil(t, fixtures, "no fixtures must be returned when the load fails")
	assert.Contains(t, err.Error(), gatewaySigningKeyName,
		"the error must name the offending file")
}
