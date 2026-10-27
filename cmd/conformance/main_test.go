package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/internal/conformance"
)

// noEnv is an environment lookup with nothing set.
func noEnv(string) (string, bool) { return "", false }

// TestRunVersionPrintsRunnerVersion asserts -version prints the
// runner version from the runtime/debug build info and exits 0
// (SDK-CONF-003).
func TestRunVersionPrintsRunnerVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-version"}, &stdout, &stderr, noEnv)

	require.Equal(t, 0, code, "-version must exit 0")
	assert.Contains(t, stdout.String(), conformance.Version(),
		"-version must print the runner version")
	assert.Empty(t, stderr.String(), "-version prints nothing to stderr")
}

// TestRunMissingConfigExitsUsageError asserts a missing required
// configuration value (base URL or operator credentials) exits
// non-zero with a usage error before any request is issued.
func TestRunMissingConfigExitsUsageError(t *testing.T) {
	var hits atomic.Int32
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(gateway.Close)

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"missing base URL", nil, "base URL"},
		{"missing operator user", []string{"-base-url", gateway.URL}, "operator user"},
		{
			"missing operator password",
			[]string{"-base-url", gateway.URL, "-operator-user", "operator"},
			"operator password",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), tc.args, &stdout, &stderr, noEnv)
			require.NotEqual(t, 0, code, "a missing required value must exit non-zero")
			assert.Contains(t, stderr.String(), tc.wantErr,
				"the usage error must name the missing value")
			assert.Contains(t, stderr.String(), "Usage",
				"a usage error must print the flag usage")
			assert.Empty(t, stdout.String(), "no case runs on a usage error")
		})
	}
	assert.Zero(t, hits.Load(), "no request may be issued before the configuration is complete")
}

// TestRunNeverPrintsOperatorPassword asserts the command reads the
// operator password from the environment only (no flag) and that no
// run output ever contains it (PRD §8).
func TestRunNeverPrintsOperatorPassword(t *testing.T) {
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(gateway.Close)

	const opPassValue = "op-pass-sentinel-91b7"
	lookup := func(name string) (string, bool) {
		if name == "CONFORMANCE_OPERATOR_PASSWORD" {
			return opPassValue, true
		}
		return "", false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var stdout, stderr bytes.Buffer
	code := run(ctx,
		[]string{"-base-url", gateway.URL, "-operator-user", "operator"},
		&stdout, &stderr, lookup)

	require.NotEqual(t, 0, code, "a 404 target must fail the run")
	combined := stdout.String() + stderr.String()
	assert.NotContains(t, combined, opPassValue,
		"the operator password must never be printed")
	assert.Contains(t, combined, "FAIL", "the run still reports case results")
}

// TestRunRejectsUnknownFlag asserts an unknown flag is a usage error
// with a non-zero exit code.
func TestRunRejectsUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-no-such-flag"}, &stdout, &stderr, noEnv)
	require.NotEqual(t, 0, code, "an unknown flag must exit non-zero")
	assert.Contains(t, stderr.String(), "no-such-flag")
}
