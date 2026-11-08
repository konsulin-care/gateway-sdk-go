# Proposal — SDK changes for backend SDK adoption

> Change proposal for `github.com/konsulin-care/gateway-sdk-go` (MIT,
> stdlib-only, currently `v0.1.0`), raised while planning the backend's
> adoption of the SDK. Companion: `../proposal-gateway.md` (gateway-side
> changes, IDs `GWP-*`). SDK requirements by `SDKP-*` ID, priority
> `M`/`S`/`C`. Versioning lives in §4 at the end. The SDK's contract
> authority (Bruno collections, golden vectors, `COMPATIBILITY.md`) is
> unchanged.
>
> Requirements now come from backend adoption **and** the gateway's
> conformance CI (ADR-020); SDKP-009 is the first CI-driven item.

## 1. Context

- SDK `v0.1.0` covers the full party surface: enrollment, key rotation,
  identities, approvals, listings, payments, webhooks, verify middleware,
  identity hashing, envelope, `gatewaytest`, conformance runner.
- The backend consumes it behind a single adapter package
  (`internal/app/drivers/gateway`), pinned to a semver tag.
- Several gaps block the backend migration: no way to bind a sealed
  payload to its invocation, no way to resolve a recipient's `use:enc`
  key without knowing its `kid`, unsigned service identity on deliveries,
  no redirect fields on payment creation, no typed settlement parsing.
- The gateway's conformance CI (ADR-020) runs the SDK conformance runner
  against the gateway and surfaces runner gaps; SDKP-009 is the first
  item driven by it.
- All changes below are additive, shipped as SDK `v0.2.0` paired with the
  gateway release carrying GWP-002 / GWP-003 (§4).

## 2. Requirements

### SDKP-001 (M) — Bound Envelope helpers

**Problem.** BK-FED-002 / GWP-003 make every crossing payload a *Bound
Envelope*: a wrapper (`{v, from, to, service, iat, nonce, data}`) sealed
inside the compact JWE, binding the ciphertext to its delivery. The SDK
offers only raw `envelope.Seal` / `Open`, so every party would hand-roll
the wrapper and its checks.

**Proposal.**
1. `envelope.SealBound(payload, kid, recipientPub, binding)` returns the
   compact JWE with the wrapper as plaintext. `binding` carries `from`,
   `to`, `service`, `iat`, `nonce`.
2. `envelope.OpenBound(compact, decrypter, expectations, cache, clock)`
   opens the JWE, checks `v` (unknown rejected), `from`, `to`, `service`,
   `iat` (older than 5 min or >60 s in the future rejected) and dedupes
   the nonce via the `ReplayCache` — scope `(from, nonce)`, retention ≥
   10 min.
3. `expectations` derives from the already-verified delivery claims
   (`sub`, `aud`, `service`, `iat`) — callers never pass values the token
   didn't cover (GWP-002).
4. Ship a **decrypt-only golden vector**: fixed recipient X25519 private
   key, ciphertext, expected plaintext and binding — so non-Go
   implementors (n8n `jose`) can verify interop.

**Acceptance.** Round-trip offline tests; replayed-nonce and stale-`iat`
negatives fail closed; the vector is verified by the n8n reference
sub-workflow.

### SDKP-002 (M) — Recipient enc-key resolution

**Problem.** `envelope.SelectEncKey` selects by the `kid` in the JWE
header, but a *sender* does not know the recipient's key id in advance —
it must pick the current `use:enc` key out of the recipient's party JWKS
before sealing.

**Proposal.**
1. A selection helper that, given only the JWKS document, returns the
   recipient's active `use:enc` key (single such key; error if none or
   ambiguous).
2. A cached resolver over `parties.JWKS`: per-party cache with a TTL,
   refetch once on seal/open failure (rotation-safe), never a tight loop.

**Acceptance.** Offline tests cover cache hit, TTL expiry, unknown-key
refetch, missing `use:enc` key.

### SDKP-003 (M) — Verify claims expose `service` and `listing_id`

**Problem.** GWP-002 adds `service` (listing name) and `listing_id` to
every `ks-delivery+jwt`. The verify package's claims struct does not carry
them, so recipients cannot do the signed comparison the Bound Envelope
requires (`from`/`to`/`service` vs claims).

**Proposal.** Add both fields to the verify claims struct; regenerate the
`ks-delivery.json` golden mirror. `verify.Ticket` and the middleware are
otherwise unchanged.

**Acceptance.** Golden vector with both claims verifies; claims readable
from the request context after the middleware.

### SDKP-004 (M) — Payment redirect fields

**Problem.** GWP-001 adds optional redirect URLs to `POST /v1/payments`;
`wire.CreatePaymentRequest` has no fields for them.

**Proposal.** Add `success_redirect_url` and `failure_redirect_url`
(`omitempty`) to `wire.CreatePaymentRequest`. No other behavior change —
validation is the gateway's.

**Acceptance.** DTO round-trip test; serialized body matches the Bruno
origin-mismatch negative example.

### SDKP-005 (S) — Typed settlement and delivery payloads

**Problem.** The backend parses settlement bodies, `external_id`, delivery
bodies and results by hand today; every party would reimplement it with
subtle drift.

**Proposal.**
1. A typed settlement-notification body: `payment_id`, `external_id`,
   `status` (`PAID` / `EXPIRED` / `CANCELED`), `payment_session_id`,
   `amount`, `currency`, `occurred_at`, `access_token_url`.
2. `wire.ParseExternalID(full)` returning `(party, domain, opaque)` with
   the known rule: three parts, and `party`, `domain`, `opaque` must not
   contain `:` (GWP-004).
3. Typed payload structs for the webhook delivery body
   `{envelope, result_ticket}`, the sync reply body (compact JWE,
   `application/jose`) and the async result body `{result}`.

**Acceptance.** Round-trip tests per type; malformed `external_id`
rejected; matches the Bruno settlement and delivery examples.

### SDKP-006 (S) — Key parsing helpers

**Problem.** The backend must turn env values (gateway `cmd/genkey`
output) into signers and JWKs; today it would hand-roll base64 and key
parsing, with no shared test vectors.

**Proposal.**
1. Parse Ed25519 private keys from the genkey output format: std base64,
   32-byte seed or 64-byte key.
2. Parse X25519 private keys from std base64 32 bytes.
3. Derive the public key, RFC 7638 `kid`, and the `use:enc` JWK for
   publishing in the party JWKS.
4. No key material ever logged or included in error strings.

**Acceptance.** Golden test: genkey-format input → public key, kid and
JWK match fixed expectations; malformed and truncated inputs fail closed.

### SDKP-007 (S) — Listings lookup

**Problem.** The backend resolves `/hook/{service}` to a listing by name
(GWP-005); the SDK's `listings.List` returns everything unfiltered.

**Proposal.** `listings.List` gains filters (`name`, `provider_party_id`,
`invocation`) matching GWP-005, plus a `FindByName(providerPartyID,
name)` helper that errors on ambiguity (0 or >1 matches among active
rows).

**Acceptance.** Offline tests: filter round-trip, single match, ambiguous
and missing name errors.

### SDKP-008 (C) — Interface and docs cleanup

1. **One shared `ReplayCache` interface** used by both `client` and
   `verify` (today two identical interfaces) — one adapter type in
   consumer code instead of two.
2. **README fix**: it still says "Pre-v0.1.0" although `v0.1.0` is tagged.
3. **PRD Go version fix**: `proposal-sdk.md` says Go 1.26; the module is
   `go 1.27`.
4. Every contract-affecting item above updates the `COMPATIBILITY.md`
   matrix row and `CHANGELOG.md` in the same PR.

**Acceptance.** Single interface compiles both call sites; docs state the
released version and Go 1.27.

### SDKP-009 (M) — Conformance runner: configurable party health URL

**Problem.** `cmd/conformance` registers the QC-chain party with the
hard-coded `defaultPartyHealthURL` `http://127.0.0.1:8080/health`
(`internal/conformance/registry.go`). `Config.PartyHealthURL` exists, but
no flag or env var populates it (`cmd/conformance/main.go` `configFrom`).
The gateway's local `scripts/conformance.sh` boots on a random free port,
so the recipient health probe hits nothing and the approvals case fails
with 502 `GW-PARTY-009`. Docker mode passes only because the container
listens on 8080.

**Proposal.**
1. Add a `-party-health-url` flag and a `CONFORMANCE_PARTY_HEALTH_URL`
   env var in `configFrom`, wired to `Config.PartyHealthURL`.
2. The flag overrides the env var, as for the other settings; unset keeps
   the current default (additive, non-breaking).
3. Gateway side (informative): `scripts/conformance.sh` already exports
   `CONFORMANCE_PARTY_HEALTH_URL` — local `http://127.0.0.1:<port>/health`,
   docker `http://127.0.0.1:8080/health`, external only when preset.

**Acceptance.** `cmd/conformance/main_test.go` covers flag, env,
flag-over-env precedence and the unset default; `cmd/conformance/README.md`,
`CHANGELOG.md` and `COMPATIBILITY.md` updated; the gateway's local
`sh scripts/conformance.sh` passes all 20 cases. Ships as `v0.1.1` (§4).

## 3. Informative — backend implementation conventions

Not SDK requirements; the conventions the backend commits to in its
adapter package (`internal/app/drivers/gateway`, the sole importer):

- **Adapter-only import**: one backend package imports the SDK; everything
  else depends on backend-owned interfaces.
- **Pinned semver tag**, no `replace` directive; upgrades Renovate-driven
  and checked against `COMPATIBILITY.md`.
- **zap → slog bridge** via `go.uber.org/zap/exp/zapslog` (SDK logger hooks
  take `*slog.Logger`).
- **Redis-backed `ReplayCache`**: atomic `SET NX PX`; deny on Redis error
  (fail closed).
- **`WithInsecureTransport` only when `APP_ENV` is local/dev/test** —
  startup fails if set in production.
- **Seller-mode `opaque`**: six FHIR ids joined with `.`, each id
  validated to contain no `.` (else 400), ≤ 512 chars total (GWP-004).
- **Magic-link fallback**: SuperTokens' built-in email delivery both when
  the gateway is unconfigured **and** when a configured gateway call
  fails (accepted risk of the dev-version SMTP path).
- **`user_ref` / `customer_ref`** = `HMAC(normalized, APP_PEPPER)` via the
  SDK `identity` package — never plaintext PII on the wire.
- **Gateway config is optional**: without `APP_GATEWAY_URL` the backend
  runs standalone; gateway-dependent endpoints (payments, hooks) answer
  503 `GATEWAY_NOT_CONFIGURED`.

## 4. Versioning

All `SDKP-*` items are additive — no breaking change to the `v0.1.0`
surface. Ship as **`v0.2.0`**, paired with the gateway release carrying
GWP-002 / GWP-003 (golden mirror updated together). `COMPATIBILITY.md`
gains the matching row; the existing release gate (green CI, manual
tagging) and Renovate-driven upgrades stay unchanged.

SDKP-009 is independent of GWP-002 / GWP-003 and ships first as
**`v0.1.1`**, ahead of `v0.2.0`; the gateway then bumps its
`conformance/go.mod` pin to `v0.1.1`.
