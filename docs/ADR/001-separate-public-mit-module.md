# ADR 001: Separate Public MIT Module

**Status:** Accepted
**Date:** 2026-10-21
**Deciders:** Konsulin central

## Context

The backend originally grew an in-repo gateway client. That couples the wire
contract to one repo's release cadence, puts the client under AGPL (no MIT
carve-out possible inside that repo), and leaves conformance as a backend
concern. Third parties building against the gateway need a client they can
adopt without license contagion, and the gateway QC needs a conformance
runner it can pin by version.

## Decision

- **Separate public module**: `github.com/konsulin-care/gateway-sdk-go` — its
  own repository, its own `go.mod`, its own semver tags, published as a public
  Go module (no registry; `proxy.golang.org` picks up the tags).
- **MIT license** (`LICENSE` already present) so both the closed-source
  gateway-adjacent tooling and the AGPL backend may depend on it.
- **Independence rule (binding)**: written fresh from the contract. Nothing is
  copied from the AGPL backend or from the gateway's reference implementations
  (`capture_verify.go`, `minter.go`, `jwe.go`). The only shared artifact is
  the **contract, not code** (ADR-003).
- **Neither side imports the other**: the gateway does not import this module,
  and this module never imports the gateway. The backend consumes it as an
  external module pinned to a semver tag behind one adapter package.
- The only data crossing the boundary is the read-only golden-vector mirror
  (ADR-004) — vectors, never signing keys (gateway key stays gateway-side).

## Consequences

**Positive:**
- Any party can `go get` the SDK without AGPL exposure.
- Independent semver and release cadence from the gateway/backend.
- First-class home for golden vectors and `cmd/conformance`; the gateway QC
  can pin the runner by tag.

**Negative:**
- Concepts are duplicated on both sides (types, checks) — drift risk handled
  by golden-vector lockstep, conformance, and `COMPATIBILITY.md` (ADR-009).
- A contract change now spans two repos and two release trains; accepted as
  the cost of licensing and cadence independence.
