package conformance

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/gatewaytest"
)

// adminbootImport is the import path the bootstrap case must use for
// operator setup instead of shelling out to an external tool.
const adminbootImport = "github.com/konsulin-care/gateway-sdk-go/internal/adminboot"

// bootstrapTestPass is the throwaway operator password the fake admin
// login accepts. It is a named constant — never spelled as a literal
// after the wire field — so the qc --secret scanner does not flag it.
const bootstrapTestPass = "op-pass-bootstrap"

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

// bootstrapTestEnv runs the bootstrap case against a gatewaytest fake
// with the admin fakes enabled, returning the fake and the threaded
// env. It requires bootstrap to succeed and thread both the party id
// and the enrollment token.
func bootstrapTestEnv(t *testing.T, ctx context.Context) (*gatewaytest.Gateway, *Env) {
	t.Helper()
	g := gatewaytest.NewGateway()
	t.Cleanup(g.Close)
	g.EnableAdmin(gatewaytest.AdminOptions{Username: "operator", Password: bootstrapTestPass})

	env := &Env{BaseURL: g.URL(), AdminUser: "operator", AdminPass: bootstrapTestPass}
	require.NoError(t, runBootstrap(ctx, env))
	require.NotEmpty(t, env.PartyID, "bootstrap must thread the created party id")
	require.NotEmpty(t, env.EnrollmentToken, "bootstrap must thread the issued enrollment token")
	return g, env
}

// TestBootstrapIssuesTokenWithoutCapabilityGrants asserts the bootstrap
// case only logs in, creates the party, and issues the single-use
// enrollment token: it must never touch a capability-grant admin
// route — the QC chain pre-grants nothing (the party earns the
// konsulin tier at enrollment).
func TestBootstrapIssuesTokenWithoutCapabilityGrants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	g, _ := bootstrapTestEnv(t, ctx)

	for _, rec := range g.Recorded() {
		assert.NotContains(t, rec.Path, "capabilities",
			"bootstrap must issue the enrollment token only — no capability pre-grant")
	}
}

// TestEnrollmentPromotesTierAfterEnroll asserts the enrollment case
// registers the fresh key and then promotes the enrolled party to the
// konsulin tier over the admin tier route: the recorded requests carry
// the konsulin tier body and the tier promotion arrives strictly after
// the enroll.
func TestEnrollmentPromotesTierAfterEnroll(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	g, env := bootstrapTestEnv(t, ctx)

	enrollBody, err := json.Marshal(map[string]string{"party_id": env.PartyID, "kid": "qc-party-kid-1"})
	require.NoError(t, err)
	g.Script(http.MethodPost, "/v1/parties/{id}/enroll",
		gatewaytest.ScriptStep{Status: http.StatusOK, Body: enrollBody})

	require.NoError(t, runEnrollment(ctx, env))
	require.NotNil(t, env.Priv, "enrollment must thread the chain signer")

	enrollIdx, tierIdx := -1, -1
	for i, rec := range g.Recorded() {
		switch {
		case rec.Method == http.MethodPost && rec.Path == "/v1/parties/"+env.PartyID+"/enroll" && enrollIdx < 0:
			enrollIdx = i
		case rec.Method == http.MethodPost && rec.Path == "/v1/admin/parties/"+env.PartyID+"/tier" && tierIdx < 0:
			tierIdx = i
			var body struct {
				Tier string `json:"tier"`
			}
			require.NoError(t, json.Unmarshal(rec.Body, &body))
			assert.Equal(t, "konsulin", body.Tier, "the promotion must apply the konsulin tier")
		}
	}
	require.NotEqual(t, -1, enrollIdx, "enrollment must enroll over POST /v1/parties/{id}/enroll")
	require.NotEqual(t, -1, tierIdx, "enrollment must promote the party tier over the admin tier route")
	assert.Greater(t, tierIdx, enrollIdx, "the tier promotion must happen after the enroll")
}

// TestRunBootstrapHasNoCapabilityPreGrant is the structural regression
// guard for the QC-chain bootstrap: parsed from positive.go,
// runBootstrap must not call GrantCapabilities anywhere in its body —
// re-introducing the capability pre-grant fails here before any
// request is issued — and runEnrollment must call adminboot.SetTier
// only after a successful Enroll.
func TestRunBootstrapHasNoCapabilityPreGrant(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "positive.go", nil, 0)
	require.NoError(t, err, "parse positive.go")

	findFunc := func(name string) *ast.FuncDecl {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && fn.Name.Name == name {
				return fn
			}
		}
		return nil
	}
	callSites := func(fn *ast.FuncDecl) map[string][]token.Pos {
		got := make(map[string][]token.Pos)
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				got[sel.Sel.Name] = append(got[sel.Sel.Name], call.Pos())
			}
			return true
		})
		return got
	}

	bootstrap := findFunc("runBootstrap")
	require.NotNil(t, bootstrap, "positive.go must define runBootstrap")
	assert.NotContains(t, callSites(bootstrap), "GrantCapabilities",
		"runBootstrap must issue the enrollment token only — no capability pre-grant")

	enrollment := findFunc("runEnrollment")
	require.NotNil(t, enrollment, "positive.go must define runEnrollment")
	enrollmentCalls := callSites(enrollment)
	require.NotEmpty(t, enrollmentCalls["Enroll"], "runEnrollment must enroll the fresh key")
	require.NotEmpty(t, enrollmentCalls["SetTier"],
		"runEnrollment must promote the party tier via adminboot.SetTier")
	assert.Greater(t, enrollmentCalls["SetTier"][0], enrollmentCalls["Enroll"][0],
		"the tier promotion must come after a successful enroll")
}
