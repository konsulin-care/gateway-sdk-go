package conformance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adminbootImport is the import path the bootstrap case must use for
// operator setup instead of shelling out to an external tool.
const adminbootImport = "github.com/konsulin-care/gateway-sdk-go/internal/adminboot"

// TestConformanceRegistryCoversQCChain asserts the registry carries every
// SDK-CONF-001 step name in QC-chain order, that the file defining the
// bootstrap run function imports internal/adminboot, and that no file in
// the package imports os/exec (SDK-CONF-001: the SDK drives the gateway
// over HTTP, never subprocesses).
func TestConformanceRegistryCoversQCChain(t *testing.T) {
	cases := Registry()

	var positive []string
	for _, c := range cases {
		if c.Kind != KindPositive {
			continue
		}
		positive = append(positive, c.Name)
		require.NotNil(t, c.Run, "positive case %q has no run function", c.Name)
	}
	assert.Equal(t, QCChainNames, positive,
		"positive cases must list every SDK-CONF-001 step name in QC-chain order")

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	require.NotEmpty(t, files, "no package sources found")

	fset := token.NewFileSet()
	bootstrapFile := ""
	for _, path := range files {
		file, err := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, err, "parse %s", path)

		importsAdminboot := false
		for _, imp := range file.Imports {
			pkg := strings.Trim(imp.Path.Value, `"`)
			require.NotEqual(t, "os/exec", pkg, "%s imports os/exec", path)
			if pkg == adminbootImport {
				importsAdminboot = true
			}
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name.Name != "runBootstrap" {
				continue
			}
			require.True(t, importsAdminboot,
				"%s defines runBootstrap without importing %s", path, adminbootImport)
			bootstrapFile = path
		}
	}
	require.NotEmpty(t, bootstrapFile, "no file defines the bootstrap case run function")
}
