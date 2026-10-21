# Phase 4 — Integration, Conformance & Release

## Objective

Close the loop end to end: offline e2e flows in `internal/integration`
(enroll → signed calls → approval → direct exchange with envelope →
callback via middleware), the admin bootstrap chain, the conformance
runner (positive + negative) run against a throwaway gateway in CI,
README recipes, release docs, DCO, and the **v0.1.0** tag.

## Depends on

- `docs/tasks/01-foundation-test-kit.md` (auth, test kit, golden vectors).
- `docs/tasks/02-inbound-trust.md` (verify middleware, envelope).
- `docs/tasks/03-client-and-routes.md` (client, retry, every §9.6 route).
- Bootstrap tooling already in place: `scripts/e2e-gateway.sh`,
  `mise run e2e-gateway`, CI `e2e-gateway` job (to be extended here).

## Requirement IDs

- `SDK-TEST-002` — backend adapter and each integration point testable
  against `gatewaytest` offline (the `internal/integration` flows).
- `SDK-CONF-001` — `cmd/conformance` runs against a **live gateway** end
  to end, bootstrapping through the admin API
  (`POST /v1/admin/auth/login` → `POST /v1/admin/parties` →
  `POST /v1/admin/parties/{id}/enrollment-token`), then exercising
  enrollment, rotation, JWKS, identities, approvals, listings, payments,
  webhooks, and result callback.
- `SDK-CONF-002` — negative cases: wrong signing key, replayed
  enrollment token, wrong/missing `typ`, `body_sha256` mismatch, expired
  token, unknown `kid` after one refetch, revoked party, missing
  capability (`capability_denied`), idempotency replay (byte-identical
  response).
- `SDK-CONF-C01` — one command exits non-zero on any contract mismatch
  with the failing case named.
- `SDK-CONF-003` — runner versioned with `v0.x` tags; the gateway-side
  `qc --flow` pin is **after v0.1.0, M5, gateway work** — not this repo's
  deliverable here.
- `SDK-README-001` — runnable recipes: enrollment, signed calls, callback
  middleware, direct exchange, and fetching the federation pepper
  (enqueue/sync-invoke the `federation-pepper` listing, keep the sealed
  JWE as received, `envelope.Open` at startup into memory only).

## Files to create/edit

Create:

- `internal/integration/enroll_test.go`,
  `internal/integration/signed_calls_test.go`,
  `internal/integration/exchange_test.go`,
  `internal/integration/callback_test.go`,
  `internal/integration/main_test.go` — no build tag, offline, zero
  network
- `internal/adminboot/login.go`, `internal/adminboot/parties.go`,
  `internal/adminboot/capabilities.go`, `internal/adminboot/adminboot_test.go`
  (against `gatewaytest` fakes; never exported publicly)
- `internal/conformance/runner.go`, `internal/conformance/positive.go`,
  `internal/conformance/negative.go`,
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
2. **enroll flow** — failing test: generate keypair, `kid` from RFC 7638
   thumbprint, PoP `body_sha256` over exact POST bytes, enroll against
   the fake; then `enroll_test.go` passes.
3. **signed calls + retry** — failing test: party-authenticated calls
   with fresh `jti` per attempt, idempotency stable across a 409→200
   replay; then `signed_calls_test.go`.
4. **direct exchange** — failing test: `approvals.Mint` → recipient runs
   the six rules → `envelope.Seal` to the recipient's `use:enc` key →
   recipient `Open`; then `exchange_test.go`.
5. **callback** — failing test: delivery token through `verify`
   middleware with `webhook_id` dedupe; then `callback_test.go`.
6. **adminboot** — failing tests per step (login → create party → issue
   enrollment token → grant capabilities) against `gatewaytest`; implement
   the three files; keep the package `internal/`.
7. **conformance** — failing registry test first (cases named, runner
   returns per-case results, first mismatch exits non-zero naming the
   case); then `positive.go` (QC-chain happy path per SDK-CONF-001) and
   `negative.go` (each SDK-CONF-002 case); wire `cmd/conformance/main.go`
   and prove `go run ./cmd/conformance` now exits non-zero with a named
   failing case when pointed at a mismatching target.
8. **throwaway gateway** — extend `scripts/e2e-gateway.sh` +
   `.github/workflows/pr-check.yml` e2e-gateway job: start pinned
   private image → `/health` 200 → run conformance → stop/remove
   container; never production.
9. **release docs** — README recipes (test each snippet), CONTRIBUTING /
   SECURITY / CHANGELOG / COMPATIBILITY tables, DCO check enabled.
10. Run `go test -race ./...` and `mise run qc` after every step.

## Definition of Done

- [ ] `go test -race ./internal/integration/...` green offline (no
      network) and wired as the CI `e2e-offline` job — green on every PR.
- [ ] Offline e2e covers all five flows: enroll → signed calls →
      approval → direct exchange with envelope → callback via middleware.
- [ ] `internal/adminboot` bootstraps login → party → enrollment token →
      capabilities against `gatewaytest`; package stays `internal/`.
- [ ] `cmd/conformance` runs positive + negative cases; each
      SDK-CONF-002 negative case present; one mismatch exits non-zero
      naming the failing case (SDK-CONF-C01).
- [ ] CI `e2e-gateway` job (and `scripts/e2e-gateway.sh`) runs
      conformance against the throwaway gateway: start → `/health` 200 →
      conformance green → container removed.
- [ ] README recipes complete per SDK-README-001, including federation
      pepper (sealed JWE opened into memory only, never written to disk
      or env).
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
  gateway side.
