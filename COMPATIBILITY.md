# Compatibility

The gateway ↔ SDK ↔ conformance-runner version matrix (ADR-009, PROPOSAL.md
§12). Consumers pin SDK tags and consult this table before upgrading; every
contract-affecting PR updates this table and [CHANGELOG.md](CHANGELOG.md)
together.

## Version matrix

| Gateway | SDK | Conformance runner | Notes |
|---------|-----|--------------------|-------|
| Development-mode releases — the wire contract mirrored from gateway commit `e93314fd` (pinned by hash in [`testdata/golden/MANIFEST.json`](testdata/golden/MANIFEST.json)); e2e exercises the `ghcr.io/konsulin-care/konsulin-gateway:latest` image | `v0.1.0` | `v0.1.0` (`go run ./cmd/conformance`, versioned with the module per SDK-CONF-003) | **Conformance runs against development-mode gateways only** (`APP_MODE=development`: no admin TOTP secret, raised `APP_RATE_*` limits, plain-HTTP callback receivers via `APP_OUTBOUND_ALLOW_INSECURE`) — the throwaway e2e profile, never production. The gateway-side `qc --flow` runner pin lands after v0.1.0 (M5, gateway work). |

## How to read this

- **Golden-vector lockstep**: the SDK's contract is the mirrored vectors in
  `testdata/golden/` (ADR-004). A gateway change to the wire contract
  regenerates the mirror, refreshes the manifest's `gateway_commit`, and
  updates this table in the same PR — so a row's gateway commit names the
  exact contract the SDK verifier was built and tested against.
- **Runner versioning**: the conformance runner ships inside this module and
  carries the module's `v0.x` tags (SDK-CONF-003). Each SDK tag names a
  matching runner version in this table — the `v0.1.0` tag ships runner
  `v0.1.0` (`go run ./cmd/conformance -version`). Once v0.1.0 exists, the
  gateway pins the runner version in `qc --flow` (gateway-side, M5
  follow-up); until then, drift is caught by this repo's own CI — the
  e2e-gateway job runs the in-repo runner against the current gateway image
  on every PR and weekly.
- **Release gate**: an SDK tag is cut only from a `master` commit with green
  CI — the `quality`, `e2e-offline`, and `e2e-gateway` conformance jobs
  (ADR-009; `docs/ARCHITECTURE.md` §7). Tagging is a manual maintainer step,
  never automated, and happens only after the green run. The tag PR updates
  this table and [CHANGELOG.md](CHANGELOG.md) together so both carry the
  matching conformance-runner version for the tag.
- **Conformance target**: the runner's supported target is a
  **development-mode** gateway (as started by `scripts/e2e-gateway.sh
  --conformance`). Production gateways reject the plain-HTTP callback
  receiver and rate-limit the QC-chain burst, so a production run is not a
  supported configuration.
- **v0 semver**: minors may break, never silently — each break is a
  CHANGELOG entry plus a row change here, in the same PR. At 1.0.0 the
  policy tightens to strict semver (a future ADR marks the transition).
- **Transport**: the SDK is `https`-only; `client.WithInsecureTransport` is
  for local dev/test against throwaway gateways, never production.
