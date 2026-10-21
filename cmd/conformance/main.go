// Command conformance runs the SDK conformance suite against a live gateway
// (SDK-CONF-001 through SDK-CONF-C01). It is a thin entry point: all case
// logic lives in internal/conformance.
//
// This stub prints "not implemented" to stderr and exits 1 until the runner is
// built in phase task 04-integration-and-release.
package main

import (
	"fmt"
	"os"
)

// main reports the unimplemented state and exits non-zero.
func main() {
	fmt.Fprintln(os.Stderr, "not implemented")
	os.Exit(1)
}
