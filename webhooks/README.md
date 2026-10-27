# webhooks

**Purpose**: webhook routes per PRD §9.6 — `Enqueue` (`POST /v1/webhooks`),
`Sync` (`POST /v1/webhooks/sync`; relays the provider's
`X-Quota-Remaining` response header verbatim on 2xx for provider-metered
listings, omitted when the provider sent none), `Status`
(`GET /v1/webhooks/{id}/status`), `Result` (`POST /v1/webhooks/{id}/result`,
party-auth path), and `ResultWithTicket` (same route over the
**single-use result ticket**, `auth:ticket`). Inbound deliveries/results and
the gateway→buyer `payment-required`/`service-receipt` event pushes arrive
at the party's own endpoints and are covered by `verify` middleware
(SDK-VERIFY), not by this package.

**Allowed imports** (PRD §7 dependency rules): standard library, `client`,
`auth`, `wire`.

**Related requirements**: SDK-API-001, SDK-API-002.

**Files** (actual):
- `webhooks.go` — `Client`, `New(cli, gatewayURL)`, `Enqueue`, `Sync`
  (returns `SyncResult` with the verbatim `QuotaRemaining`), `Status`,
  `Result` methods (context, `*wire.Error`; `Idempotency-Key` on the
  creates)
- `result.go` — `ResultWithTicket` (single attempt, generated
  `Idempotency-Key`, ticket as the Bearer credential), `ResultOption`,
  `WithResponseMeta` (captures `client.ResponseMeta` incl. the sent key
  on success and failure alike)
- `doc.go` — package doc
- `webhooks_test.go` — route tests against `gatewaytest` fakes

**Built by**: `docs/tasks/03-client-and-routes.md`.

## `ResultWithTicket` outcome table

`ResultWithTicket` presents the caller's single-use `ks-result+jwt`
ticket verbatim as `Authorization: Bearer` and makes exactly **one**
network attempt, whatever the bound client's retry policy says — the
route is the engine's terminal step and is never auto-retried. Each
call generates one `Idempotency-Key`; `WithResponseMeta` exposes the
sent key in the captured header on success and on failure alike.

| Gateway answer | Result of the call | Outcome class |
| --- | --- | --- |
| `202` accepted | decoded `*wire.WebhookResultResponse` (`status: "accepted"`) | known success |
| `400` bad request (missing/empty `result`) | `*wire.Error` | known failure |
| `401` `GW-HOOK-007` (invalid or already-used ticket) | `*wire.Error` keeping code `GW-HOOK-007` | known failure — never matches `client.ErrOutcomeUnknown` |
| `404` (unknown webhook, or a foreign caller — no existence disclosure) | `*wire.Error` | known failure |
| transport failure, or a retryable status (e.g. `503` `GW-HOOK-009`) after the single attempt | error wrapping `client.ErrOutcomeUnknown`, last failure kept in the chain | **unknown** — the result may or may not have been applied (fail closed) |

## Same-key manual recovery after `ErrOutcomeUnknown`

When `errors.Is(err, client.ErrOutcomeUnknown)` the SDK has deliberately
stopped — recovery is manual and must reuse the **same**
`Idempotency-Key`:

1. Register `WithResponseMeta` on the call before sending; the capture
   fires on the failed attempt too and carries the generated
   `Idempotency-Key` (`Header.Get("Idempotency-Key")`).
2. Do **not** blindly re-call `ResultWithTicket`: every call mints a
   fresh key, and the gateway scopes keys per caller/method/path — a new
   key is a *different* operation.
3. Re-submit the result **manually with the captured key and a
   byte-identical body**. Same key + same body replays the gateway's
   stored 2xx (`Idempotent-Replay: true`, kept 24 h) if the lost attempt
   actually applied, or executes the result fresh if it never landed —
   never twice. A fresh key on an applied attempt would re-execute
   against a consumed single-use ticket and answer `401 GW-HOOK-007`;
   a changed body under the same key fails `422 GW-HOOK-008`.
4. `Status` (`GET /v1/webhooks/{id}/status`) is the observation hook
   for the row's delivery state (`pending` / `delivered` / `failed`) at
   any point in the sequence.
