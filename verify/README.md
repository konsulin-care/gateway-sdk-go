# verify

**Purpose**: the inbound trust layer — gateway JWKS cache with TTL and one
rate-limited refetch per unknown `kid` (then fail closed), per-kind token
checks for all six token kinds (`ks-event+jwt` accepts exactly four
purposes: `settlement-notification`, `service-result`, `payment-required`,
`service-receipt`), the six Recipient Verification Rules verbatim,
callback middleware wrapping `http.Handler` with `webhook_id`/`jti` dedupe
through `ReplayCache` — an alias of `wire.ReplayCache`, so one cache
implementation satisfies `wire`, `client`, `verify`, and `gatewaytest` —
and the in-memory default `MemoryReplayCache`. Decoded `Claims` carry the
conditional delivery-token `Service` and `ListingID` claims (empty when
absent, exposed via `ClaimsFromContext`). Decoding is forward-compatible
(unknown claim names ignored) while
selection stays fail-closed (unknown `typ`/`kid` deny — ADR-012).

**Allowed imports** (PRD §7 dependency rules): standard library, `internal/jws`,
`internal/jwk`, `wire`.

**Related requirements**: SDK-VERIFY-001, SDK-VERIFY-002, SDK-VERIFY-003,
SDK-VERIFY-004, SDK-VERIFY-C01 (deny-unknown-`typ`/`kid` half of
SDK-WIRE-004).

**Files**:
- `doc.go` — package doc (allowed imports, requirement IDs)
- `errors.go` — sentinel errors for `errors.Is` (`ErrTyp`, `ErrIssuer`,
  `ErrAudience`, `ErrExpired`, `ErrClaims`, `ErrPurpose`, `ErrBodyHash`,
  `ErrUnknownKid`, `ErrSignature`, `ErrReplay`, `ErrUnsupportedKind`)
- `options.go` — verifier options (`WithHTTPClient`, `WithTTL`,
  `WithRefetchInterval`, `WithClock`, `WithReplayCache`,
  `WithReplayRetention`) and middleware options (`WithMaxBodyBytes`)
- `replay.go` — `ReplayCache` (type alias of `wire.ReplayCache`) plus the
  `ScopeJTI`/`ScopeWebhookID` scope aliases, and the in-memory default
  (`NewMemoryReplayCache`, concurrency-safe, evicts after `until`)
- `jwks_cache.go` — TTL cache, bounded refetch window, rotation (current + previous key)
- `claims.go` — decoded token claims type (`Claims`, incl. the conditional
  delivery-token `Service` and `ListingID` fields)
- `checks.go` — exact `typ`, `iss`, `aud`, `exp`/`iat` (60 s skew), `body_sha256`, per-kind claims
- `middleware.go` — `http.Handler` wrapper, raw body buffered exactly once, `webhook_id` dedupe, `ClaimsFromContext`
- `rules.go` — `Ticket` and the six Recipient Verification Rules
- tests: `replay_test.go`, `jwks_cache_test.go`, `checks_test.go`,
  `middleware_test.go`, `rules_test.go`, `helpers_test.go`,
  `verify_test.go`, `claims_service_test.go` (each ≤ 300 lines)

**Built by**: `docs/tasks/02-inbound-trust.md`.
