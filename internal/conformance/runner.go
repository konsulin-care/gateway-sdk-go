package conformance

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"time"
)

// Exit codes the conformance command returns (SDK-CONF-C01).
const (
	// ExitOK is the exit code of a green run.
	ExitOK = 0
	// ExitMismatch is the exit code when any case mismatches.
	ExitMismatch = 1
	// ExitUsage is the exit code for a configuration error detected
	// before any request is issued.
	ExitUsage = 2
)

// defaultCaseTimeout bounds each case of a live run so a stalled step
// (e.g. the result-callback wait on a gateway that never delivers)
// can never hang the command forever.
const defaultCaseTimeout = 90 * time.Second

// Run executes the full ordered case registry against cfg and reports
// one result line per executed case on stdout plus the failing case
// names on stderr. It returns ExitOK when every case passes,
// ExitMismatch when any case mismatches, and ExitUsage when cfg is
// missing a required value — detected before any request is issued.
// The operator password is never printed (PRD §8).
//
// Parameters: ctx bounds the whole run; cfg carries the target and
// operator configuration; stdout and stderr receive the report.
// Returns: the process exit code (ExitOK, ExitMismatch, ExitUsage).
func Run(ctx context.Context, cfg *Config, stdout, stderr io.Writer) int {
	return runRegistry(ctx, cfg, Registry(), stdout, stderr)
}

// runRegistry executes cases against cfg: it validates the
// configuration before any request is issued, starts the
// result-callback receiver, threads the configured callback URL and
// party health URL into the case Env (an unset callback URL falls
// back to the receiver's loopback URL via Env.callbackURL()), and
// reports the per-case results.
//
// Parameters: ctx bounds the run; cfg carries the target and operator
// configuration; cases is the registry slice to execute; stdout and
// stderr receive the report.
// Returns: the process exit code (ExitOK, ExitMismatch, ExitUsage).
func runRegistry(ctx context.Context, cfg *Config, cases []Case, stdout, stderr io.Writer) int {
	if err := cfg.Validate(); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	callback, err := newCallbackReceiver(cfg.CallbackAddr)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	defer callback.Close()
	env := &Env{
		BaseURL:        cfg.BaseURL,
		AdminUser:      cfg.OperatorUser,
		AdminPass:      cfg.OperatorPass,
		Callback:       callback,
		CallbackURL:    cfg.CallbackURL,
		PartyHealthURL: cfg.PartyHealthURL,
	}
	return runCases(ctx, cases, env, cfg.timeout(), stdout, stderr)
}

// runCases executes cases in order against env, prints one result
// line per executed case to stdout (PASS or FAIL plus the case name),
// prints each failing case name to stderr, and returns ExitMismatch
// when any case failed and ExitOK otherwise. timeout > 0 bounds each
// case individually; zero leaves the parent context unbounded.
//
// Parameters: ctx bounds the run; cases is the registry slice to
// execute; env is the shared case environment; timeout is the
// per-case bound; stdout and stderr receive the report.
// Returns: ExitOK when every case passed, ExitMismatch otherwise.
func runCases(ctx context.Context, cases []Case, env *Env, timeout time.Duration, stdout, stderr io.Writer) int {
	failed := make([]string, 0)
	for _, c := range cases {
		err := runCase(ctx, c, env, timeout)
		if err == nil {
			_, _ = fmt.Fprintf(stdout, "PASS %s\n", c.Name)
			continue
		}
		_, _ = fmt.Fprintf(stdout, "FAIL %s: %v\n", c.Name, err)
		failed = append(failed, c.Name)
	}
	for _, name := range failed {
		_, _ = fmt.Fprintf(stderr, "FAIL %s\n", name)
	}
	if len(failed) > 0 {
		_, _ = fmt.Fprintf(stderr, "conformance: %d of %d cases failed\n", len(failed), len(cases))
		return ExitMismatch
	}
	return ExitOK
}

// runCase executes one case, applying the per-case timeout when set.
func runCase(ctx context.Context, c Case, env *Env, timeout time.Duration) error {
	if timeout <= 0 {
		return c.Run(ctx, env)
	}
	caseCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return c.Run(caseCtx, env)
}

// newCallbackReceiver starts the plain-HTTP result-callback receiver:
// bound to addr (host:port) when set, on an ephemeral loopback
// listener otherwise.
func newCallbackReceiver(addr string) (*CallbackReceiver, error) {
	if addr == "" {
		return NewCallbackReceiver(), nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("conformance: callback listen on %s: %w", addr, err)
	}
	r := &CallbackReceiver{notify: make(chan struct{}, 1)}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(r.handle))
	srv.Listener = ln
	srv.Start()
	r.server = srv
	return r, nil
}
