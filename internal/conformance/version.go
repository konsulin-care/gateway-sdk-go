package conformance

import "runtime/debug"

// Version returns the conformance runner version (SDK-CONF-003) as
// reported by the Go build info of the running binary: the module
// version when built from a released module tag (e.g. "v0.1.0"), or
// "devel" for a local build whose build info carries no version. The
// raw "(devel)" marker is normalized so output stays uniform.
//
// Returns: the runner version, never empty.
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "devel"
	}
	switch v := info.Main.Version; v {
	case "", "(devel)":
		return "devel"
	default:
		return v
	}
}
