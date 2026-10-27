// Command conformance runs the SDK conformance suite against a live
// gateway (SDK-CONF-001 through SDK-CONF-C01). It is a thin entry
// point: it resolves the target configuration from flags and
// environment, invokes the runner in internal/conformance, and exits
// with its exit code — 0 on a green run, 1 when a case mismatches
// (named on stderr), 2 on a usage error (SDK-CONF-C01).
//
// Usage:
//
//	conformance [-base-url url] [-operator-user user] [-callback addr] [-version]
//
// The operator password comes from CONFORMANCE_OPERATOR_PASSWORD
// only; the command deliberately exposes no password flag and no TOTP
// input. The runner version comes from the Go build info
// (SDK-CONF-003). The operator password is never printed (PRD §8).
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/konsulin-care/gateway-sdk-go/internal/conformance"
)

// The flag and environment names the command accepts. The password has
// an environment name only — there is no password flag by design.
const (
	envBaseURL      = "CONFORMANCE_BASE_URL"
	envOperatorUser = "CONFORMANCE_OPERATOR_USER"
	envOperatorPass = "CONFORMANCE_OPERATOR_PASSWORD"
	envCallbackAddr = "CONFORMANCE_CALLBACK_ADDR"
)

// main wires the real environment into run and exits with its code.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv))
}

// run parses args (flags override the environment), prints the runner
// version on -version, and returns the process exit code:
// conformance.ExitOK, conformance.ExitMismatch, or
// conformance.ExitUsage. The operator password is read from
// CONFORMANCE_OPERATOR_PASSWORD only and is never printed.
//
// Parameters: ctx bounds the run; args are the command arguments
// without the program name; stdout and stderr receive the report and
// usage errors; lookup reads the environment.
// Returns: the process exit code.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, lookup func(string) (string, bool)) int {
	fs := flag.NewFlagSet("conformance", flag.ContinueOnError)
	fs.SetOutput(stderr)
	baseURL := fs.String("base-url", "", "gateway base URL (or "+envBaseURL+")")
	operatorUser := fs.String("operator-user", "", "admin operator username (or "+envOperatorUser+")")
	callbackAddr := fs.String("callback", "",
		"result-callback listen address host:port (or "+envCallbackAddr+"; empty binds an ephemeral loopback listener)")
	showVersion := fs.Bool("version", false, "print the runner version and exit")
	if err := fs.Parse(args); err != nil {
		return conformance.ExitUsage
	}
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, "conformance runner", conformance.Version())
		return conformance.ExitOK
	}
	cfg := &conformance.Config{
		BaseURL:      firstSet(*baseURL, envValue(lookup, envBaseURL)),
		OperatorUser: firstSet(*operatorUser, envValue(lookup, envOperatorUser)),
		OperatorPass: envValue(lookup, envOperatorPass),
		CallbackAddr: firstSet(*callbackAddr, envValue(lookup, envCallbackAddr)),
	}
	if err := cfg.Validate(); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		fs.Usage()
		return conformance.ExitUsage
	}
	return conformance.Run(ctx, cfg, stdout, stderr)
}

// envValue reads name from the environment, empty when unset.
func envValue(lookup func(string) (string, bool), name string) string {
	v, _ := lookup(name)
	return v
}

// firstSet returns the flag value when set, else the environment
// value — flags override the environment.
func firstSet(flagVal, envVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return envVal
}
