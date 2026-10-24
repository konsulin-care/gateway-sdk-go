# Phase 4 — Integration, Conformance & Release

## Objective

Close the loop end to end: offline e2e flows in `internal/integration`
(enroll → signed calls → approval → direct exchange with envelope →
callback via middleware), the admin bootstrap chain, the conformance
runner (positive + negative) run against a throwaway gateway in CI,
README recipes, release docs, DCO, and the **v0.1.0** tag.

## Ground rules

Each checklist item is one `SDK-*` behavior: the behavior, its accept/deny
expectation, and the test (or release gate) that proves it. TDD — write the
named failing test first, then implement. Every offline test runs with zero
network and reads only in-module paths; the gateway checkout and the
throwaway image are authoring-time / CI-time references only, never unit-
test dependencies (AGENTS.md). Re-run `go test -race ./...` and
`mise run qc` after each item.

## Depends on

- `docs/tasks/.archive/01-foundation-test-kit.md` (auth, test kit, golden
  vectors — landed).
- `docs/tasks/02-inbound-trust.md` (verify middleware, envelope).
- `docs/tasks/03-client-and-routes.md` (client, retry, every §9.6 route).
- Bootstrap tooling already in place: `scripts/e2e-gateway.sh`,
  `mise run e2e-gateway`, CI `e2e-gateway` job (to be extended here).

## Checklist

### `SDK-TEST-002` — offline integration against `gatewaytest`

- [ ] **Behavior**: the backend adapter's integration points are testable
  against `gatewaytest` with zero network.
- **Accept**: the five `internal/integration` flows (enroll → signed
  calls → approval → direct exchange → callback) run green with no
  network reachable.
- **Deny**: any test that needs the real gateway belongs in conformance
  (SDK-CONF), not here — a network dial in this package fails review.
- **Proving test**: `TestIntegrationFlowsOffline`
  (`internal/integration/main_test.go` proves zero-network by
  construction).

### `SDK-CONF-001` — conformance runner against a live gateway

- [ ] **Behavior**: `cmd/conformance` exercises the QC-chain party surface
  end to end, bootstrapping through the admin API
  (`POST /v1/admin/auth/login` → `POST /v1/admin/parties` →
  `POST /v1/admin/parties/{id}/enrollment-token`) in its own code, then
  enrollment, rotation, JWKS, identities, approvals, listings, payments,
  webhooks, and the result callback.
- **Accept**: every step above runs and reports pass against a healthy
  gateway target.
- **Deny**: a missing step (or a bootstrap step that shells out to
  external tooling) fails the registry test.
- **Proving tests**: `TestConformanceRegistryCoversQCChain` (offline
  registry coverage), plus `mise run e2e-gateway -- conformance` against
  the throwaway gateway.

### `SDK-CONF-002` — negative cases

- [ ] **Behavior**: wrong signing key, replayed enrollment token,
  wrong/missing `typ`, `body_sha256` mismatch, expired token, unknown
  `kid` after one refetch, revoked party, missing capability
  (`capability_denied`), idempotency replay (byte-identical response).
- **Accept**: only the honest case passes; each negative case is a named
  failing observation against a target that behaves correctly.
- **Deny**: a negative case that passes against a correct gateway (i.e.
  proves nothing) fails the registry test.
- **Proving test**: `TestConformanceNegativeCasesAllNamed`.

### `SDK-CONF-C01` — one command, non-zero on mismatch

- [ ] **Behavior**: a single command exits non-zero on any contract
  mismatch with the failing case named.
- **Accept**: a green run exits 0 and names each executed case.
- **Deny**: one mismatched case → non-zero exit, case name on stderr.
- **Proving tests**: `TestConformanceMismatchExitsNonZeroNamingCase`,
  `TestConformanceGreenRunExitsZero`.

### `SDK-CONF-003` — runner versioning

- [ ] **Behavior**: the runner is versioned with `v0.x` module tags. The
  gateway-side `qc --flow` pin is **after v0.1.0, M5, gateway work** —
  not this repo's deliverable here.
- **Accept**: each SDK tag carries a matching runner version (checked at
  release).
- **Deny**: a tag without a versioned runner is a release-gate failure —
  no unit test proves this; the gate is `mise run qc` + the tagged
  release checklist below.
- **Proving gate**: release checklist (§12 Release) — `CHANGELOG.md` +
  `COMPATIBILITY.md` row in the tag PR.

### `SDK-README-001` — runnable recipes

- [ ] **Behavior**: README carries runnable recipes for enrollment, signed
  calls, callback middleware, direct exchange, and fetching the
  federation pepper (enqueue/sync-invoke the `federation-pepper`
  listing, keep the sealed JWE as received, `envelope.Open` at startup
  with the party's `Decrypter` into memory only — never to disk or env).
- **Accept**: each snippet compiles and its flow is exercised by an
  `internal/integration` test path.
- **Deny**: a snippet that does not compile (or that writes plaintext
  pepper anywhere) fails review before the tag.
- **Proving test**: `TestReadmeRecipesMatchPublicAPI` (snippets against
  the public surface) + the SDK-TEST-002 flows for the recipe flows.

## Files to create/edit

Create:

- `internal/integration/main_test.go`,
  `internal/integration/enroll_test.go`,
  `internal/integration/signed_calls_test.go`,
  `internal/integration/exchange_test.go`,
  `internal/integration/callback_test.go` — no build tag, offline, zero
  network
- `internal/adminboot/login.go`, `internal/adminboot/parties.go`,
  `internal/adminboot/capabilities.go`,
  `internal/adminboot/adminboot_test.go` (against `gatewaytest` fakes;
  never exported publicly)
- `internal/conformance/registry.go`, `internal/conformance/runner.go`,
  `internal/conformance/positive.go`, `internal/conformance/negative.go`,
  `internal/conformance/conformance_test.go`
- `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `COMPATIBILITY.md`
- DCO check config (CI workflow/job or DCO app) — enabled before the
  first external PR

Edit:

- `cmd/conformance/main.go` — replace the "not implemented" stub with
  flags, runner invocation (`internal/conformance`), exit code
- `scripts/e2e-gateway.sh` — add a conformance mode that runs
  `cmd/conformance` against the freshly started throwaway gateway
- `.github/workflows/pr-check.yml` — extend the `e2e-gateway` job to run
  the conformance pass after `mise run e2e-gateway --smoke`
- `README.md` — replace the stub with the PRD §9.11 recipes
- `internal/integration/README.md`, `internal/adminboot/README.md`,
  `internal/conformance/README.md`, `cmd/conformance/README.md` — update
  planned lists if files split differently

## Direction (TDD)

1. **integration setup** — failing `main_test.go`: shared offline fixture
   wiring (`gatewaytest` server, minted tokens, deterministic
   `ReplayCache`), zero network proven by construction.
2. **enroll flow** — failing `TestIntegrationFlowsOffline` path: generate
   keypair, `kid` from RFC 7638 thumbprint, PoP `body_sha256` over exact
   POST bytes, enroll against the fake.
3. **signed calls + retry** — party-authenticated calls with fresh `jti`
   per attempt, idempotency stable across a 409→200 replay with a new
   key only after a terminal 402 (ADR-011).
4. **direct exchange** — `approvals.Mint` → recipient runs the six rules
   → `envelope.Seal` to the recipient's `use:enc` key → `Open`.
5. **callback** — delivery token through `verify` middleware with
   `webhook_id` dedupe; include a `payment-required`/`service-receipt`
   `ks-event+jwt` (four accepted purposes, task 02).
6. **adminboot** — failing tests per step (login → create party → issue
   enrollment token → grant capabilities) against `gatewaytest`; keep the
   package `internal/`.
7. **conformance** — failing registry test first (`TestConformanceRegistryCoversQCChain`);
   then `positive.go` (QC-chain happy path per SDK-CONF-001) and
   `negative.go` (each SDK-CONF-002 case); wire `cmd/conformance/main.go`
   so a mismatch exits non-zero naming the case.
8. **throwaway gateway** — extend `scripts/e2e-gateway.sh` +
   `.github/workflows/pr-check.yml` e2e-gateway job: start pinned
   private image → `/health` 200 → run conformance → stop/remove
   container; never production.
9. **release docs** — README recipes (test each snippet), CONTRIBUTING /
   SECURITY / CHANGELOG / COMPATIBILITY tables, DCO check enabled.
10. Run `go test -race ./...` and `mise run qc` after every step.

## Definition of Done

- [ ] Every checklist item's proving test (or gate) green; accept and
      deny expectations both asserted.
- [ ] `go test -race ./internal/integration/...` green offline and wired
      as the CI `e2e-offline` job — green on every PR.
- [ ] `internal/adminboot` bootstraps login → party → enrollment token →
      capabilities against `gatewaytest`; package stays `internal/`.
- [ ] `cmd/conformance` runs positive + negative cases; one mismatch
      exits non-zero naming the failing case (SDK-CONF-C01).
- [ ] CI `e2e-gateway` job runs conformance against the throwaway
      gateway; no CI or unit test reads `../gateway` (drift is the
      local-only `mise run qc --mirror-check`).
- [ ] README recipes complete per SDK-README-001, including federation
      pepper (opened into memory only, never written to disk or env).
- [ ] CONTRIBUTING, SECURITY, CHANGELOG, COMPATIBILITY.md present;
      COMPATIBILITY table rows for gateway ↔ SDK ↔ conformance-runner.
- [ ] DCO check enabled and passing before the first external PR.
- [ ] `go test -race ./...` and `mise run qc` green; **v0.1.0 tagged**
      only with green CI + green conformance.

## Open items

- Payments end-to-end needs **Xendit test-mode credentials** or a
  gateway payment-drill path — decide which before marking the payments
  conformance cases mandatory (may ship skipped-with-reason initially).
- Gateway outbound is **https-only**, which blocks plain-http callback
  receivers in tests — needs a TLS test server (self-signed cert +
  opted-in transport) or a gateway dev escape hatch; confirm with the
  gateway side (authoring-time).
